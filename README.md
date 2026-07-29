<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/relintio-logo-dark.svg">
    <img src="./assets/relintio-logo-light.svg" alt="Relintio" width="260">
  </picture>

  <h1>Relintio.Agent</h1>

  <p>
    <a href="https://www.nuget.org/packages/Relintio.Agent"><img alt="nuget" src="https://img.shields.io/nuget/v/Relintio.Agent?color=efd420"></a>
    <a href="https://dotnet.microsoft.com"><img alt="net" src="https://img.shields.io/badge/.NET-8.0-efd420"></a>
    <a href="./LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-efd420"></a>
  </p>

  <p><strong>The Relintio agent for ASP.NET Core.</strong></p>
</div>

---

ASP.NET Core middleware that scores every request inside your own process. It keeps a rule set synchronized from the control plane on a background task — every ten seconds or so, with jitter and exponential backoff — and decides allow, challenge or block against the cached copy, with no network round trip on the request path. Telemetry drains through a bounded channel, so a slow control plane costs a queue slot rather than a response. The package references only the shared framework.

```csharp
using Relintio;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var agent = new Agent(new AgentConfig
{
    LicenseKey = Environment.GetEnvironmentVariable("UP_LICENSE_KEY") ?? string.Empty,
    ApiUrl = "https://api.relintio.com/v1",
    Domain = "example.com",
    SyncIntervalSeconds = 10,
});

agent.StartSync();
app.Lifetime.ApplicationStopping.Register(agent.Dispose);

app.UseRelintio(agent);

app.MapGet("/", () => "ok");

app.Run();
```

## Installation

```bash
dotnet add package Relintio.Agent
```

Targets `net8.0` and takes a `FrameworkReference` on `Microsoft.AspNetCore.App` — no NuGet dependencies of its own, so it cannot pull a transitive version into an argument with the rest of your solution.

## Registration

`UseRelintio` must come before any middleware that answers on its own — a cache, a static-file handler or an authentication scheme that short-circuits will serve the request before the agent ever scores it, and the diff looks identical either way. Position relative to your endpoints is not the trap it is in some frameworks: `UseRelintio` is an ordinary `UseMiddleware` component, and `WebApplication` appends the endpoint terminal at build time, so the agent runs before your endpoint executes whether the call sits above or below `MapGet`. If you call `UseRouting` explicitly, put `UseRelintio` before it.

The middleware resolves the client address itself, in the order the reference PHP agent uses: `CF-Connecting-IP`, then the first entry of `X-Forwarded-For`, then `X-Real-IP`, then `HttpContext.Connection.RemoteIpAddress`. Each candidate has to parse as an IP address before it is accepted, so a junk or injected header falls through to the next one rather than erasing the real address. It used to read the socket alone, which behind any load balancer, CDN or reverse proxy meant every request appeared to come from one address and every `ip` rule matched the proxy or nothing.

The order is the security-relevant part, not a preference. Behind Cloudflare, `CF-Connecting-IP` is written by the edge while `X-Forwarded-For` still carries whatever the caller put at the front, so reading the forwarded list first would let a caller choose the address every `ip` rule is keyed on.

The forwarded headers are trusted unconditionally — as they are in every other SDK in the fleet. An application reachable without going through your proxy will therefore accept whatever a caller claims. Terminate that at the proxy, or keep the container off the public network. You may still run `UseForwardedHeaders` ahead of this for the benefit of the rest of your pipeline; the agent no longer depends on it.

## Configuration

`AgentConfig` is a plain settings object; nothing validates it. An empty `LicenseKey` produces requests the control plane rejects rather than an exception at startup, so read it from configuration where its absence is visible.

| Property | Type | Default | Meaning |
| --- | --- | --- | --- |
| `LicenseKey` | `string` | `""` | Required in practice. **Secret** — see below. |
| `ApiUrl` | `string` | `https://api.relintio.com/v1` | Trailing slashes are stripped. |
| `Domain` | `string` | `""` | The licensed domain, sent on every sync. |
| `SyncIntervalSeconds` | `int` | `10` | Target cadence. Floored at 10; jitter and backoff apply on top. |
| `RequestTimeoutSeconds` | `int` | `10` | `HttpClient.Timeout`. Floored at 1. |

There is a second constructor, `Agent(AgentConfig, HttpMessageHandler?)`, which exists so the transport can be substituted — a corporate proxy, a retry policy, or a test double that captures what actually goes on the wire. That last case is why it is public: the signing tests assert against the bytes a handler received, which is the only way to catch a body that was re-encoded after it was signed. Pass `null` for the default handler.

The licence key is a **secret**. It signs every outbound call and it is the HMAC key a passport is minted under, so anything holding it can forge both. Keep it in the environment or a secret store, never in a repository, and never anywhere it can reach a browser — that is what publishable keys are for, and they belong to the React and Shopify SDKs, not this one.

## What happens on a request

Every request is scored on the client address, the `User-Agent` header, the path and the request headers; the result is queued for telemetry, and the middleware either answers or calls the next one. Nothing is passed through unscored — `/_relintio/challenge` and `/_relintio/verify` used to be, and since this SDK serves neither, that was an unscored path and nothing else.

Rules are additive. Each one that matches contributes its score and may escalate the action; the totals then decide on their own:

| Total score | Action |
| --- | --- |
| 0–49 | allow |
| 50–99 | challenge |
| 100 or more | block |

A rule whose own action is `block` blocks whatever the total says. A rule marked `challenge` escalates unless something already said block.

The dashboard assigns 100 to a block rule and 60 to a challenge rule, which has a consequence worth knowing before you write the third rule: **two challenge rules matching the same request add to 120 and block it.** Nothing warns you, and the dashboard still calls both rules challenges.

| `type` | Compared against | Condition |
| --- | --- | --- |
| `ip` | client IP | `equals` |
| `path` | request path | `contains` |
| `user_agent` | `User-Agent` header | `contains` |
| `header` | the request headers | `contains` |

`contains` is `OrdinalIgnoreCase`, and so is `equals` — invisible for a path, and real for an IPv6 address written `2001:DB8::1` in the dashboard and sent lowercase on the wire. That is why `contracts/rule-conditions-v1.json` settles it rather than leaving each runtime to choose. An empty value or an empty pattern never matches.

A `header` rule carries its own small grammar in the pattern. Without a colon it names a header and tests that it is present with a non-empty value; an empty header is not a signal. With one — `X-Forwarded-Host: evil.example` — the part before names the header and the part after is matched against its value, case-insensitively on both sides, with the whitespace around the colon trimmed. A repeated header is joined the way HTTP defines it, so a rule sees every value under a name and not just the first.

`regex` is a fourth condition the dashboard does not emit today. It is evaluated with `System.Text.RegularExpressions` — as a regular expression, not as a substring — under a 100 ms match timeout, and a pattern that will not compile or will not finish is skipped rather than thrown out of the decision path, where the only thing to catch it would be the visitor. An unrecognised type or condition contributes nothing, deliberately: a rule that silently means something else is worse than one that does nothing.

`RuleConditionsConformanceTests` loads that contract file and asserts every vector in it, so this agent cannot drift from the other eleven without a red build.

Block is `403` with a self-contained HTML page. Challenge is also `403`, carrying `X-Relintio-Action: challenge` and `X-Relintio-Challenge-URL`, plus a body that redirects. Those two headers are exactly what the React SDK's interceptor watches for, so a React front end talking to this agent opens the challenge overlay and replays the request that was refused.

The URL in that header is the hosted challenge page. `Agent.ChallengeAsync` asks `POST /agent/challenge/init` for an opaque token and redirects to `/security-check` on the platform's public host — the licence key never appears in it. It used to be `/_relintio/challenge`, which this package registers no endpoint for and the middleware used to skip, so the challenge tier was a redirect into your own 404.

`ChallengeAsync` returns a `ChallengeOutcome` with three cases rather than a nullable URL, because the answer has three shapes:

| `Kind` | What the middleware does |
| --- | --- |
| `Redirect` | `403` plus the two headers |
| `Disabled` with `ShouldBlock` | blocks — the customer turned the challenge off and asked for these to be blocked |
| `Disabled` without it | calls the next middleware — the customer turned the challenge off and asked for these to be let through |
| `Unavailable` | blocks — no challenge was issued, so nothing was passed |

`challenge_disabled` arrives as a `200` because it is a policy answer and not a failure. Collapsing it into the same absent-URL as "the call failed" is what made an entire risk band silently allow in another SDK.

The last row used to call the next middleware too, and that was wrong in a way the middle row is not. A request only reaches this branch because the engine already judged it suspicious enough to challenge; when the token service times out or answers with something unusable, no challenge was issued and nothing was passed, so that verdict still stands. Failing open there makes an unreachable control plane the way in for exactly the traffic the challenge tier exists to stop, and it put this SDK at odds with the reference PHP agent, Node, Go and Ruby, all of which block.

## Passport v2

`Passport` is a static, dependency-free implementation of the v2 token: `v2.<base64url payload>.<base64url signature>`, HMAC-SHA256 under the licence key, carrying an absolute expiry and a binding hash. Verification is entirely local, because the edge has to keep deciding when the control plane is unreachable. Both the signature and the binding are compared with `CryptographicOperations.FixedTimeEquals`.

The binding is `sha256(licenceKey|userAgent|acceptLanguage)` truncated to 16 hex characters, over the **raw** header values. Trim them, lowercase them or cap them for logging and this agent computes a different hash from the challenge server, which locks out every visitor who just passed.

It replaced `sha256("verified" + licenceKey)` — one constant string, the same for every visitor of a site, valid for a week. One leaked cookie bypassed the agent until the key was rotated. Tokens in that shape are no longer parsed at all.

### `Passport` moved to `namespace Relintio`

This is a **source-breaking change**. `using Relintio.Agent;` no longer resolves; use `using Relintio;`, which is the same namespace as `Agent`, `AgentConfig` and `Middleware`, so most files need one line changed and nothing else.

It moved because it could not stay. `Relintio.Agent` is a *type*, and a namespace of the same name cannot coexist with it inside one assembly — the compiler answers `CS0101: The namespace 'Relintio' already contains a definition for 'Agent'` and refuses the whole build. From outside the assembly the two collide more quietly, as `CS0435`, and the consumer's own namespace wins. Either way `Relintio.Agent.Passport` was not a name anything could reliably reach, which is why nothing in this SDK ever called it and why it went untested until it was moved.

**`Middleware` still does not use it.** The middleware never reads the cookie and never redeems an `up_token`; the only part of `Passport` the shipped agent calls is `SigningHeaders`. Verification and minting are primitives for you to wire into whatever handles your challenge exchange:

```csharp
public static bool Holds(HttpRequest request, string licenseKey)
    => Passport.Verify(
        request.Cookies[Passport.Cookie],
        licenseKey,
        request.Headers.UserAgent.ToString(),
        request.Headers.AcceptLanguage.ToString()) is not null;

public static void Issue(HttpContext context, string licenseKey, long ttlFromToken)
{
    var ttl = Passport.ClampTtl(ttlFromToken);

    var value = Passport.Mint(
        ttl,
        licenseKey,
        context.Request.Headers.UserAgent.ToString(),
        context.Request.Headers.AcceptLanguage.ToString());

    context.Response.Cookies.Append(Passport.Cookie, value, new CookieOptions
    {
        Path = "/",
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        MaxAge = TimeSpan.FromSeconds(ttl),
    });
}
```

Pass the token's ttl through `ClampTtl` first — it arrives signed, but a bug upstream should not be able to mint a ten-year cookie. `Passport.ClockSkewSeconds` is the 60 seconds of drift allowed between the challenge server and this process.

## Request signing

Every outbound ingest call carries:

```
X-Relintio-Timestamp: 1785120000
X-Relintio-Nonce:     <16–128 chars of [A-Za-z0-9_-]>
X-Relintio-Signature: v1=<64 hex>
```

The signature is `HMAC-SHA256("v1:" + timestamp + ":" + nonce + ":" + sha256(body), licenceKey)`. The server checks the timestamp within ±300 seconds, the nonce unused within 600 seconds for that credential, and the signature in constant time — burning the nonce last, so a forged request cannot consume one the real agent is about to use.

`agent_signature_mode` on the server has three settings. `off` checks nothing. `optional` allows an absent signature but still rejects a bad one, so corrupting the header cannot be used as a downgrade. `required` rejects unsigned ingest with `401`, and is both the default and the steady state.

Every call goes through one private `PostSignedAsync`, which serialises the payload once and sends that same `byte[]` as `ByteArrayContent`. This is the part that is easy to get wrong, and `PostAsJsonAsync` — which this replaced — got it wrong: it takes the object and encodes it a second time inside the client, leaving the signature over bytes that never went on the wire and that the server cannot reproduce. Every call fails, with nothing in any log to say why. An endpoint added around the chokepoint rather than through it does not degrade gracefully; it `401`s, and the edge goes blind. The three headers are attached with `TryAddWithoutValidation`, because `System.Net.Http` does not know them and the validating overload rejects what it cannot parse into a typed value.

`tests/Relintio.Agent.Tests/SignedRequestTests.cs` catches exactly the re-encoding bug, by capturing a real outbound request through the handler overload and recomputing the signature from the bytes that arrived.

## Edge cases

**Nothing is protected until the first sync lands.** The rule list starts empty and an empty list scores zero, so every request is allowed. `StartSync()` runs the first sync on a background task, not inline — `await agent.SyncRulesAsync()` once before you start serving if you need rules in place from the first request.

**A dead control plane is a silent allow, not an outage.** The sync loop swallows every exception and a failed sync leaves the previous rules in place. A `200` carrying no `rules` array counts as a failure for the same reason: an unknown status, an error envelope or an empty object is not a policy, and applying it as one would empty the cache and leave the site unprotected. That is what `quota_exceeded` used to do deliberately — a billing state switching off a defence — and what any unrecognised answer did by accident. Failures back off to a five-minute ceiling with jitter on every interval, so a fleet restarting together does not synchronize into a thundering herd. There is no inactive-licence handling in this agent: an expired subscription stops new rules arriving, it does not start refusing traffic.

**Telemetry is dropped rather than queued forever.** `QueueTelemetry` writes into a 1024-slot channel with `BoundedChannelFullMode.DropWrite`, so when the control plane is reachable but slow the newest events are discarded and the request path stays fast. `SendTelemetryAsync` is the awaitable version and does not drop, but it also does not belong on a request thread.

**Clean traffic is sampled at 1%.** `Agent.AllowSampleRate` is fixed at `0.01` and must match `UsageMeterService::ALLOW_SAMPLE_RATE` on the platform, which multiplies a reported allow back up by it to estimate real traffic. Reporting every allowed request — which this SDK used to do — inflates the customer's meter a hundredfold against an install of the compiled engine on the same plan. It is a constant rather than a setting for that reason. Blocks, challenges, decoys and slows are never sampled: they are the security record, and the platform counts them at face value.

**`Dispose` is best-effort.** It cancels the sync loop, completes the telemetry channel and waits two seconds for both to finish before disposing the rest. Register it on `ApplicationStopping`, as in the quickstart, or the loop outlives the app in a host that reuses the process.

**Machine callers score like bots.** curl, `HttpClient` with no headers set and Go's default client look nothing like a browser. Exclude health checks and webhooks with dashboard bypass rules — never by lowering protection globally, and never by carving out login, registration, checkout or password reset.

## In production

Start in observe mode, watch a day of real traffic, and only then enforce. The dashboard shows what the agent scored and why, so the question to settle before enforcement is whether the traffic you expect is scored the way you expect.

Run at least one deploy with `agent_signature_mode` at `optional` and the adoption page open. It records which credentials are signing and which are not, and that is the only way to know whether flipping to `required` will take part of the fleet dark.

## Links

- [Documentation](https://relintio.com/docs)
- [Quickstart](https://relintio.com/docs/quickstart/dotnet)
- [API reference](https://relintio.com/docs/api-reference)
- [Licenses](https://relintio.com/licenses)

Security reports go to **support@relintio.com**, not to a public issue.

## License

MIT. See [LICENSE](./LICENSE).
