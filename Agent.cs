using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Relintio
{
    public class AgentConfig
    {
        public string LicenseKey { get; set; } = string.Empty;
        public string ApiUrl { get; set; } = "https://api.relintio.com/v1";
        public string Domain { get; set; } = string.Empty;
        public int SyncIntervalSeconds { get; set; } = 10;
        public int RequestTimeoutSeconds { get; set; } = 10;
    }

    public class WafRule
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("pattern")]
        public string Pattern { get; set; } = string.Empty;

        [JsonPropertyName("condition")]
        public string Condition { get; set; } = string.Empty;

        [JsonPropertyName("score")]
        public int Score { get; set; }

        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;
    }

    /// <summary>
    /// What /agent/verify answers with.
    /// </summary>
    /// <remarks>
    /// <c>Rules</c> is nullable and defaults to null so that "the field was
    /// absent" is distinguishable from "the field was an empty list". A control
    /// plane that answers with something this agent does not recognise leaves it
    /// null, and a null ruleset must never overwrite the one already in force.
    /// </remarks>
    public class SyncResponse
    {
        [JsonPropertyName("rules")]
        public List<WafRule>? Rules { get; set; }

        [JsonPropertyName("status")]
        public string? Status { get; set; }
    }

    public class WafResult
    {
        public int Score { get; set; }
        public string Action { get; set; } = "allow";
    }

    /// <summary>
    /// The result of asking the control plane to start a challenge.
    /// </summary>
    /// <remarks>
    /// Three outcomes, because the answer has three shapes and a nullable URL
    /// only has two. "The licence has the challenge switched off, and the
    /// customer's fallback says block these" is not the same thing as "the call
    /// failed", and treating them as one is what made an entire risk band
    /// silently allow in another SDK.
    /// </remarks>
    public sealed class ChallengeOutcome
    {
        public enum ChallengeKind
        {
            /// <summary>Send the visitor to <see cref="Url"/>.</summary>
            Redirect,

            /// <summary>
            /// The licence has the challenge switched off, or the plan does not
            /// include it. <see cref="ShouldBlock"/> carries the customer's
            /// chosen fallback, so this is not the same as "no challenge
            /// available" and must not be treated as one.
            /// </summary>
            Disabled,

            /// <summary>
            /// The control plane could not be reached, or answered with
            /// something unusable. No challenge was issued, so nothing was
            /// passed and the visitor is blocked — the same answer the
            /// reference PHP agent, Node, Go and Ruby give.
            /// </summary>
            Unavailable
        }

        private ChallengeOutcome(ChallengeKind kind, string? url, bool shouldBlock)
        {
            Kind = kind;
            Url = url;
            ShouldBlock = shouldBlock;
        }

        public ChallengeKind Kind { get; }

        /// <summary>The hosted challenge page; null unless <see cref="Kind"/> is Redirect.</summary>
        public string? Url { get; }

        /// <summary>Meaningful only when <see cref="Kind"/> is Disabled.</summary>
        public bool ShouldBlock { get; }

        internal static ChallengeOutcome Redirect(string url) => new(ChallengeKind.Redirect, url, false);

        internal static ChallengeOutcome Disabled(bool shouldBlock) => new(ChallengeKind.Disabled, null, shouldBlock);

        internal static ChallengeOutcome Unavailable() => new(ChallengeKind.Unavailable, null, false);
    }

    public class Agent : IDisposable
    {
        private const string AgentVersion = "0.1.9";

        /// <summary>
        /// Fraction of allowed requests reported to the platform.
        /// </summary>
        /// <remarks>
        /// Must match <c>UsageMeterService::ALLOW_SAMPLE_RATE</c> on the platform,
        /// and <c>AgentPayloadService::LOG_ALLOW_SAMPLE_RATE</c> in the compiled
        /// engine. All three feed one meter: the platform multiplies a reported
        /// ALLOW back up by this rate to estimate real traffic, and that
        /// correction is only valid if every agent samples at the same rate. This
        /// agent used to report every allowed request, which inflated the
        /// customer's meter a hundredfold against an install of the compiled
        /// engine on the same plan.
        /// <para>
        /// Blocks, challenges, decoys and slows are never sampled: they are the
        /// security record, and the platform counts them at face value.
        /// </para>
        /// </remarks>
        public const double AllowSampleRate = 0.01;
        private readonly AgentConfig _config;
        private readonly HttpClient _httpClient;
        private List<WafRule> _rules = new();
        private readonly ReaderWriterLockSlim _lock = new();
        private CancellationTokenSource? _cts;
        private Task? _syncTask;
        private readonly CancellationTokenSource _lifetime = new();
        private readonly Channel<TelemetryItem> _telemetry;
        private readonly Task _telemetryTask;

        private sealed record TelemetryItem(string Ip, string UserAgent, string Path, WafResult Result);

        public Agent(AgentConfig config) : this(config, null)
        {
        }

        /// <summary>
        /// Lets the host supply the transport — a corporate proxy, a retry
        /// policy, or a test double that captures what actually goes on the
        /// wire. Pass null for the default handler.
        /// </summary>
        public Agent(AgentConfig config, HttpMessageHandler? handler)
        {
            _config = config;
            _httpClient = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: true);
            _httpClient.Timeout = TimeSpan.FromSeconds(Math.Max(1, _config.RequestTimeoutSeconds));
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _telemetry = Channel.CreateBounded<TelemetryItem>(new BoundedChannelOptions(1024)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
                SingleReader = true,
                SingleWriter = false
            });
            _telemetryTask = Task.Run(ProcessTelemetryAsync);
        }

        public void StartSync()
        {
            if (_syncTask is { IsCompleted: false })
            {
                return;
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            _syncTask = Task.Run(() => SyncLoop(_cts.Token));
        }

        public void StopSync()
        {
            _cts?.Cancel();
        }

        private async Task SyncLoop(CancellationToken token)
        {
            var failures = 0;
            while (!token.IsCancellationRequested)
            {
                var success = false;
                try
                {
                    success = await SyncRulesInternalAsync(token);
                }
                catch when (!token.IsCancellationRequested)
                {
                    // Fail-open
                }

                failures = success ? 0 : Math.Min(failures + 1, 5);
                var baseDelay = Math.Min(300, Math.Max(10, _config.SyncIntervalSeconds) * (1 << failures));
                var delay = Math.Max(8, (int)Math.Round(baseDelay * (0.8 + Random.Shared.NextDouble() * 0.4)));

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(delay), token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        public async Task SyncRulesAsync(CancellationToken cancellationToken = default)
        {
            await SyncRulesInternalAsync(cancellationToken);
        }

        private async Task<bool> SyncRulesInternalAsync(CancellationToken cancellationToken)
        {
            var url = $"{_config.ApiUrl.TrimEnd('/')}/agent/verify";
            var payload = new
            {
                license_key = _config.LicenseKey,
                domain = _config.Domain,
                protocol_version = 1,
                agent_kind = "dotnet",
                agent_version = AgentVersion,
                capabilities = new[] { "custom_rules", "telemetry" }
            };
            using var response = await PostSignedAsync(url, payload, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var data = JsonSerializer.Deserialize<SyncResponse>(json);

                // A null `rules` means this is not a policy — an unknown status,
                // an error envelope, an empty object. Keep enforcing the last
                // policy and report the sync as failed so it is retried.
                // Overwriting `_rules` here is how `quota_exceeded` used to
                // switch a customer's protection off over a billing state, and
                // any answer this agent did not recognise would have done the
                // same thing. An explicit `"rules": []` is a real, empty policy
                // and is applied.
                if (data?.Rules == null)
                {
                    return false;
                }

                _lock.EnterWriteLock();
                try
                {
                    _rules = data.Rules;
                }
                finally
                {
                    _lock.ExitWriteLock();
                }

                return true;
            }

            return false;
        }

        public WafResult CheckRequest(string ip, string userAgent, string path)
            => CheckRequest(ip, userAgent, path, null);

        public WafResult CheckRequest(string ip, string userAgent, string path, IReadOnlyDictionary<string, string>? headers)
        {
            _lock.EnterReadLock();
            try
            {
                int score = 0;
                string action = "allow";

                foreach (var rule in _rules)
                {
                    bool matched = false;
                    switch (rule.Type.ToLower())
                    {
                        case "ip":
                            matched = MatchValue(ip, rule.Pattern, rule.Condition);
                            break;
                        case "user_agent":
                            matched = MatchValue(userAgent, rule.Pattern, rule.Condition);
                            break;
                        case "path":
                            matched = MatchValue(path, rule.Pattern, rule.Condition);
                            break;
                        case "header":
                            matched = MatchHeader(headers, rule.Pattern, rule.Condition);
                            break;

                        // Any other type is one this agent does not know, and it
                        // scores nothing: a rule that quietly means something
                        // else is worse than one that does nothing.
                    }

                    if (matched)
                    {
                        score += rule.Score;
                        if (rule.Action == "block")
                        {
                            action = "block";
                        }
                        else if (rule.Action == "challenge" && action != "block")
                        {
                            action = "challenge";
                        }
                    }
                }

                if (score >= 100)
                {
                    action = "block";
                }
                else if (score >= 50 && action != "block")
                {
                    action = "challenge";
                }

                return new WafResult { Score = score, Action = action };
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        /// <summary>
        /// Asks the control plane to start a challenge for this visitor.
        /// </summary>
        /// <remarks>
        /// The redirect is to the hosted <c>/security-check</c> page, carrying
        /// an opaque token. This used to be <c>/_relintio/challenge</c> — a path
        /// this SDK never serves and used to skip — so the challenge tier was a
        /// redirect into a dead end, and every request in the challenge band was
        /// re-scored on the way back with nothing to show for it.
        ///
        /// Goes through <see cref="PostSignedAsync"/> like everything else:
        /// challenge/init sits behind the same signature middleware as the
        /// ingest endpoints, so an unsigned call here would 401 the request that
        /// should have sent a suspicious visitor to the challenge — and an
        /// unchallenged visitor is an allowed one.
        /// </remarks>
        /// <param name="returnUrl">absolute URL to send the visitor back to once they pass</param>
        public async Task<ChallengeOutcome> ChallengeAsync(string returnUrl, CancellationToken cancellationToken = default)
        {
            JsonElement body;

            try
            {
                var url = $"{_config.ApiUrl.TrimEnd('/')}/agent/challenge/init";
                using var response = await PostSignedAsync(
                    url, new { license_key = _config.LicenseKey, return_url = returnUrl }, cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    return ChallengeOutcome.Unavailable();
                }

                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                body = document.RootElement.Clone();
            }
            catch
            {
                return ChallengeOutcome.Unavailable();
            }

            if (body.ValueKind != JsonValueKind.Object)
            {
                return ChallengeOutcome.Unavailable();
            }

            // The customer has switched the challenge off, or their plan does
            // not include it. This is a policy answer carrying what to do
            // instead, and it arrives as a 200 for exactly that reason.
            if (Field(body, "status") == "challenge_disabled")
            {
                return ChallengeOutcome.Disabled(Field(body, "fallback") != "allow");
            }

            // An absolute URL from the control plane wins, and is read before
            // the token: a response can legitimately supply one without the
            // other.
            var supplied = Field(body, "challenge_url");
            if (supplied is not null
                && (supplied.StartsWith("https://", StringComparison.Ordinal)
                    || supplied.StartsWith("http://", StringComparison.Ordinal)))
            {
                return ChallengeOutcome.Redirect(supplied);
            }

            var token = Field(body, "token");
            if (string.IsNullOrEmpty(token))
            {
                return ChallengeOutcome.Unavailable();
            }

            return ChallengeOutcome.Redirect($"{PlatformWebUrl()}/security-check?token={Uri.EscapeDataString(token)}");
        }

        private static string? Field(JsonElement body, string name)
            => body.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

        /// <summary>
        /// The public site behind the ingest API: https://api.relintio.com/v1 is
        /// where the agent talks, https://relintio.com is where a visitor goes.
        /// </summary>
        private string PlatformWebUrl()
        {
            if (!Uri.TryCreate(_config.ApiUrl, UriKind.Absolute, out var api))
            {
                return _config.ApiUrl.TrimEnd('/');
            }

            var host = api.Host.StartsWith("api.", StringComparison.OrdinalIgnoreCase) ? api.Host[4..] : api.Host;
            var port = api.IsDefaultPort ? string.Empty : $":{api.Port}";

            return $"{api.Scheme}://{host}{port}";
        }

        public async Task SendTelemetryAsync(string ip, string userAgent, string path, WafResult result, CancellationToken cancellationToken = default)
        {
            try
            {
                var url = $"{_config.ApiUrl.TrimEnd('/')}/agent/log";
                var payload = new
                {
                    license_key = _config.LicenseKey,
                    ip,
                    user_agent = userAgent,
                    path,
                    risk_score = Math.Clamp(result.Score, 0, 100),
                    action = result.Action.ToUpperInvariant(),
                    reason_code = "sdk_rule",
                    protocol_version = 1,
                    agent_kind = "dotnet",
                    agent_version = AgentVersion
                };

                using var response = await PostSignedAsync(url, payload, cancellationToken);
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                // Fail-open
            }
        }

        /// <summary>
        /// Every call this agent makes to the ingest API goes through here.
        ///
        /// The server rejects unsigned calls outright once
        /// <c>agent_signature_mode</c> is <c>required</c>, which is its default,
        /// so an endpoint added around this rather than through it is not
        /// degraded — it is a 401 and a silently blind edge.
        ///
        /// The payload is serialised once and that same array is both what gets
        /// signed and what gets sent. PostAsJsonAsync, which this replaced, took
        /// the object and encoded it a second time inside the client: the
        /// signature would then cover bytes that never went on the wire, which
        /// the server cannot reproduce and the agent cannot see itself doing.
        /// </summary>
        /// <remarks>
        /// Generic rather than taking <c>object</c>: the payloads are anonymous
        /// types, and an <c>object</c> parameter would hand the serialiser a
        /// declared type whose property set is not the one the caller wrote.
        /// </remarks>
        private async Task<HttpResponseMessage> PostSignedAsync<TPayload>(string url, TPayload payload, CancellationToken cancellationToken)
        {
            var body = JsonSerializer.SerializeToUtf8Bytes(payload);

            // Built before the message so the content type is set on a
            // reference the compiler knows is non-null, rather than read back
            // off the message's nullable Content property.
            var content = new ByteArrayContent(body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

            // TryAddWithoutValidation because these are not headers
            // System.Net.Http knows, and the validating overload rejects
            // anything it cannot parse into a typed value.
            foreach (var header in Passport.SigningHeaders(body, _config.LicenseKey))
            {
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return await _httpClient.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// Whether this decision is one of the ones reported. An allow is sampled
        /// at <see cref="AllowSampleRate"/>; everything else goes in full.
        /// </summary>
        public static bool ReportsAction(string action)
        {
            if (!string.Equals(action, "allow", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return Random.Shared.NextDouble() <= AllowSampleRate;
        }

        public void QueueTelemetry(string ip, string userAgent, string path, WafResult result)
        {
            if (!ReportsAction(result.Action))
            {
                return;
            }

            _telemetry.Writer.TryWrite(new TelemetryItem(ip, userAgent, path, result));
        }

        private async Task ProcessTelemetryAsync()
        {
            try
            {
                await foreach (var item in _telemetry.Reader.ReadAllAsync(_lifetime.Token))
                {
                    await SendTelemetryAsync(item.Ip, item.UserAgent, item.Path, item.Result, _lifetime.Token);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
        }

        /// <summary>
        /// contracts/rule-conditions-v1.json, which is the one definition of
        /// what a condition means across the twelve SDKs.
        /// </summary>
        /// <remarks>
        /// <c>equals</c> folds case. The only type the platform emits it for is
        /// <c>ip</c>, and an IPv6 address carries hex letters that two runtimes
        /// render in different cases, so an ordinal comparison made one
        /// dashboard rule match in Java and not here.
        ///
        /// Anything that is not one of the three known conditions contributes
        /// nothing. Falling through to a substring search — which is what this
        /// did — makes an unrecognised rule match something other than what its
        /// author wrote, and that is worse than a rule that does nothing.
        /// </remarks>
        private bool MatchValue(string value, string pattern, string condition)
        {
            if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(pattern))
                return false;

            return condition.ToLower() switch
            {
                "equals" => string.Equals(value, pattern, StringComparison.OrdinalIgnoreCase),
                "contains" => value.Contains(pattern, StringComparison.OrdinalIgnoreCase),
                "regex" => MatchRegex(value, pattern),
                _ => false
            };
        }

        /// <summary>
        /// A pattern the author got wrong is a broken rule, never a broken
        /// request: an uncompilable expression is skipped rather than thrown out
        /// of the decision path, where the only thing to catch it would be the
        /// visitor. The timeout is there for the same reason — a catastrophically
        /// backtracking pattern must not be able to hold a request thread.
        /// </summary>
        private bool MatchRegex(string value, string pattern)
        {
            try
            {
                return Regex.IsMatch(value, pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }

        /// <summary>
        /// A <c>header</c> rule, whose pattern carries its own grammar.
        /// </summary>
        /// <remarks>
        /// Without a colon the pattern names a header and tests that it is
        /// present with a non-empty value — an empty header is not a signal.
        /// With one, the part before names the header and the part after is
        /// matched against its value, case-insensitively on both sides, with the
        /// whitespace around the colon trimmed off.
        ///
        /// AgentController has mapped a dashboard <c>header_match</c> rule to
        /// this type all along. Without this branch such a rule reached the
        /// agent, matched nothing and reported nothing, so a customer could
        /// author one, watch it save and sync, and never learn it did nothing.
        /// </remarks>
        private bool MatchHeader(IReadOnlyDictionary<string, string>? headers, string pattern, string condition)
        {
            if (headers is null || headers.Count == 0 || string.IsNullOrEmpty(pattern))
                return false;

            var colon = pattern.IndexOf(':');
            var name = (colon < 0 ? pattern : pattern[..colon]).Trim();
            var wanted = colon < 0 ? string.Empty : pattern[(colon + 1)..].Trim();

            if (name.Length == 0)
                return false;

            foreach (var header in headers)
            {
                if (!string.Equals(header.Key?.Trim(), name, StringComparison.OrdinalIgnoreCase))
                    continue;

                var value = header.Value ?? string.Empty;

                // A bare name, or `Name:` with nothing after it, carries no
                // value to compare and is read as the presence form rather than
                // as a match on every header there is.
                if (wanted.Length == 0)
                {
                    if (value.Length != 0)
                        return true;

                    continue;
                }

                if (MatchValue(value, wanted, condition))
                    return true;
            }

            return false;
        }

        public void Dispose()
        {
            StopSync();
            _telemetry.Writer.TryComplete();
            _lifetime.Cancel();
            try
            {
                Task.WhenAll(_syncTask ?? Task.CompletedTask, _telemetryTask).Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Best-effort shutdown
            }
            _cts?.Dispose();
            _lifetime.Dispose();
            _lock.Dispose();
            _httpClient.Dispose();
        }
    }
}
