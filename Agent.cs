using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Relintio
{
    public class AgentConfig
    {
        public string LicenseKey { get; set; } = string.Empty;
        public string ApiUrl { get; set; } = "https://relintio.com/api";
        public string Domain { get; set; } = string.Empty;
        public int SyncIntervalSeconds { get; set; } = 60;
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

    public class SyncResponse
    {
        [JsonPropertyName("rules")]
        public List<WafRule> Rules { get; set; } = new();
    }

    public class WafResult
    {
        public int Score { get; set; }
        public string Action { get; set; } = "allow";
    }

    public class Agent : IDisposable
    {
        private const string AgentVersion = "0.1.7";
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

        public Agent(AgentConfig config)
        {
            _config = config;
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(Math.Max(1, _config.RequestTimeoutSeconds))
            };
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
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await SyncRulesAsync(token);
                }
                catch when (!token.IsCancellationRequested)
                {
                    // Fail-open
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, _config.SyncIntervalSeconds)), token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        public async Task SyncRulesAsync(CancellationToken cancellationToken = default)
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
            using var response = await _httpClient.PostAsJsonAsync(url, payload, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync(cancellationToken);
                var data = JsonSerializer.Deserialize<SyncResponse>(json);
                if (data != null)
                {
                    _lock.EnterWriteLock();
                    try
                    {
                        _rules = data.Rules;
                    }
                    finally
                    {
                        _lock.ExitWriteLock();
                    }
                }
            }
        }

        public WafResult CheckRequest(string ip, string userAgent, string path)
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

                using var response = await _httpClient.PostAsJsonAsync(url, payload, cancellationToken);
            }
            catch when (!cancellationToken.IsCancellationRequested)
            {
                // Fail-open
            }
        }

        public void QueueTelemetry(string ip, string userAgent, string path, WafResult result)
        {
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

        private bool MatchValue(string value, string pattern, string condition)
        {
            if (string.IsNullOrEmpty(value) || string.IsNullOrEmpty(pattern))
                return false;

            return condition.ToLower() switch
            {
                "equals" => value == pattern,
                "contains" => value.Contains(pattern, StringComparison.OrdinalIgnoreCase),
                _ => value.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            };
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
