using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;

using Xunit;

namespace Relintio.Tests
{
    /// <summary>
    /// What the middleware reads off a request, and what it answers with.
    ///
    /// Two defects live here. The client IP came from
    /// <c>Connection.RemoteIpAddress</c> and nowhere else, so behind any proxy,
    /// load balancer or CDN — which is nearly every production deployment —
    /// every <c>ip</c> rule saw the proxy's address rather than the visitor's,
    /// and matched nothing or matched everyone. And a challenged visitor was
    /// redirected to <c>/_relintio/challenge</c>, a path this SDK never serves
    /// and used to skip, so the challenge tier was a redirect into a dead end.
    /// </summary>
    public class MiddlewareTests
    {
        private const string LicenseKey = "sk_live_test_key";

        // ── client IP ────────────────────────────────────────────────────────

        /// <summary>
        /// The precedence the PHP reference agent applies, header for header:
        /// CF-Connecting-IP, then the first entry of X-Forwarded-For, then
        /// X-Real-IP, then the socket. The order is the security-relevant part.
        /// Behind Cloudflare, CF-Connecting-IP is set by the edge while
        /// X-Forwarded-For has the caller's own value at the front, so reading
        /// the forwarded list first would hand an attacker the client IP every
        /// rate limit and every ip rule is keyed on.
        /// </summary>
        [Fact]
        public async Task CloudflareHeaderWinsOverAForwardedListTheCallerControls()
        {
            var seen = await Scored(request =>
            {
                request.Headers["CF-Connecting-IP"] = "203.0.113.10";
                request.Headers["X-Forwarded-For"] = "198.51.100.9, 203.0.113.10";
                request.Headers["X-Real-IP"] = "192.0.2.4";
            });

            Assert.Equal("203.0.113.10", seen);
        }

        [Fact]
        public async Task TheFirstForwardedEntryIsTheVisitor()
        {
            Assert.Equal("203.0.113.10", await Scored(request =>
                request.Headers["X-Forwarded-For"] = "203.0.113.10, 70.41.3.18, 150.172.238.178"));
        }

        [Fact]
        public async Task RealIpIsReadWhenThereIsNoForwardedList()
        {
            Assert.Equal("203.0.113.10", await Scored(request => request.Headers["X-Real-IP"] = "203.0.113.10"));
        }

        /// <summary>
        /// A header that does not hold an address is not an address. Falling
        /// through to the next candidate rather than trusting the text is what
        /// keeps a junk or injected header from erasing the real client IP.
        /// </summary>
        [Fact]
        public async Task AHeaderThatIsNotAnAddressFallsThroughToTheNextOne()
        {
            Assert.Equal("203.0.113.10", await Scored(request =>
            {
                request.Headers["CF-Connecting-IP"] = "not-an-ip";
                request.Headers["X-Forwarded-For"] = "  , 198.51.100.9";
                request.Headers["X-Real-IP"] = "203.0.113.10";
            }));
        }

        [Fact]
        public async Task TheSocketAddressIsTheLastResort()
        {
            Assert.Equal("198.51.100.23", await Scored(_ => { }));
        }

        // ── the challenge response ───────────────────────────────────────────

        /// <summary>
        /// The status and headers the React SDK's interceptor watches for, and
        /// a URL that leads to the hosted page rather than to a route this SDK
        /// does not serve.
        /// </summary>
        [Fact]
        public async Task AChallengeRedirectsToTheHostedPageAndNotToALocalDeadEnd()
        {
            var context = await Run(
                Challenging(),
                Responds(HttpStatusCode.OK, "{\"status\":\"success\",\"token\":\"abc123\"}"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.Equal("challenge", context.Response.Headers["X-Relintio-Action"].ToString());

            var url = context.Response.Headers["X-Relintio-Challenge-URL"].ToString();
            Assert.Matches("^https?://", url);
            Assert.Contains("/security-check?token=abc123", url);
            Assert.DoesNotContain("/_relintio/challenge", url);
            Assert.DoesNotContain(LicenseKey, url);
        }

        /// <summary>An absolute URL from the control plane wins outright.</summary>
        [Fact]
        public async Task AChallengeUrlSuppliedByTheControlPlaneIsUsedAsGiven()
        {
            var context = await Run(
                Challenging(),
                Responds(HttpStatusCode.OK,
                    "{\"status\":\"success\",\"token\":\"abc123\",\"challenge_url\":\"https://relintio.com/security-check?token=xyz\"}"));

            Assert.Equal(
                "https://relintio.com/security-check?token=xyz",
                context.Response.Headers["X-Relintio-Challenge-URL"].ToString());
        }

        /// <summary>
        /// <c>challenge_disabled</c> is a policy answer carrying what to do
        /// instead, and it arrives as a 200 for exactly that reason. Reading it
        /// as "no challenge available" is what made the whole challenge band
        /// silently allow in another SDK.
        /// </summary>
        [Fact]
        public async Task ADisabledChallengeHonoursABlockFallback()
        {
            var context = await Run(
                Challenging(),
                Responds(HttpStatusCode.OK, "{\"status\":\"challenge_disabled\",\"fallback\":\"block\"}"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.Equal(string.Empty, context.Response.Headers["X-Relintio-Action"].ToString());
            Assert.False(Chained, "the fallback said block and the request went through");
        }

        /// <summary>And the other fallback, which is the one a customer sets deliberately.</summary>
        [Fact]
        public async Task ADisabledChallengeHonoursAnAllowFallback()
        {
            await Run(
                Challenging(),
                Responds(HttpStatusCode.OK, "{\"status\":\"challenge_disabled\",\"fallback\":\"allow\"}"));

            Assert.True(Chained, "the customer switched the challenge off and the visitor was still stopped");
        }

        /// <summary>
        /// The third case, and the reason a nullable string will not do: an
        /// outage is not a policy, and it is not a pass either. No challenge was
        /// issued, so nothing was passed — the engine's own verdict on this
        /// visitor still stands. Failing open here makes an unreachable token
        /// service the way through for exactly the traffic the challenge tier
        /// exists to stop, and it is what put this SDK at odds with the PHP
        /// reference agent, Node, Go and Ruby, all of which block.
        /// </summary>
        [Fact]
        public async Task AControlPlaneThatCannotIssueAChallengeBlocks()
        {
            var context = await Run(Challenging(), Responds(HttpStatusCode.InternalServerError, "{}"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.Equal(string.Empty, context.Response.Headers["X-Relintio-Action"].ToString());
            Assert.False(Chained, "an unissued challenge waved a suspicious visitor through");
        }

        /// <summary>
        /// The same answer when the call never produces a response at all. A
        /// refused connection or a timeout is the shape a control-plane outage
        /// most often takes, and it reaches the middleware down a different path
        /// from an error status, so it is asserted separately.
        /// </summary>
        [Fact]
        public async Task AChallengeCallThatNeverCompletesBlocks()
        {
            var context = await Run(
                Challenging(),
                () => throw new HttpRequestException("connection refused"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.Equal(string.Empty, context.Response.Headers["X-Relintio-Action"].ToString());
            Assert.False(Chained, "an unreachable token service was treated as a pass");
        }

        /// <summary>
        /// And when the answer arrives but cannot be read. An unusable body is
        /// not a <c>challenge_disabled</c> carrying a fallback, so there is no
        /// customer choice to honour and the verdict stands.
        /// </summary>
        [Fact]
        public async Task AnUnreadableChallengeResponseBlocks()
        {
            var context = await Run(Challenging(), Responds(HttpStatusCode.OK, "not json at all"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.False(Chained, "an unreadable answer was treated as a pass");
        }

        /// <summary>A block is a block: 403, and none of the challenge signalling.</summary>
        [Fact]
        public async Task ABlockIsNotDressedUpAsAChallenge()
        {
            var context = await Run(
                new WafRule { Type = "path", Pattern = "/admin", Condition = "contains", Score = 100, Action = "block" },
                Responds(HttpStatusCode.OK, "{\"status\":\"success\",\"token\":\"abc123\"}"));

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
            Assert.Equal(string.Empty, context.Response.Headers["X-Relintio-Action"].ToString());
            Assert.False(Chained);
        }

        /// <summary>
        /// A <c>header</c> rule has to reach the matcher through the middleware,
        /// or the type is implemented and still dead for every real request.
        /// </summary>
        [Fact]
        public async Task RequestHeadersReachTheRuleEngine()
        {
            var context = await Run(
                new WafRule { Type = "header", Pattern = "X-Scanner: nuclei", Condition = "contains", Score = 100, Action = "block" },
                Responds(HttpStatusCode.OK, "{}"),
                request => request.Headers["X-Scanner"] = "nuclei");

            Assert.Equal(StatusCodes.Status403Forbidden, context.Response.StatusCode);
        }

        // ── harness ──────────────────────────────────────────────────────────

        private bool Chained;

        private static WafRule Challenging()
            => new() { Type = "path", Pattern = "/admin", Condition = "contains", Score = 60, Action = "challenge" };

        /// <summary>
        /// The IP the middleware resolved, read back out of the telemetry the
        /// agent sends rather than out of a seam that exists for the test.
        /// </summary>
        private async Task<string> Scored(Action<HttpRequest> prepare)
        {
            var bodies = new List<string>();
            var handler = new StubHandler(_ => Responds(HttpStatusCode.OK, "{}")(), bodies);

            using var agent = new Agent(Config(), handler);
            RuleConditionsConformanceTests.Seed(agent);

            var context = NewContext(prepare);
            await new Middleware(_ => { Chained = true; return Task.CompletedTask; }, agent).InvokeAsync(context);

            // Telemetry leaves on its own channel reader, so the body is waited
            // for rather than assumed to have been written already.
            for (var attempt = 0; attempt < 200 && bodies.Count == 0; attempt++)
            {
                await Task.Delay(10);
            }

            Assert.True(bodies.Count > 0, "the agent sent no telemetry, so no IP was reported");

            using var document = System.Text.Json.JsonDocument.Parse(bodies[0]);

            return document.RootElement.GetProperty("ip").GetString() ?? string.Empty;
        }

        private async Task<HttpContext> Run(
            WafRule rule,
            Func<HttpResponseMessage> response,
            Action<HttpRequest>? prepare = null)
        {
            using var agent = new Agent(Config(), new StubHandler(_ => response(), new List<string>()));
            RuleConditionsConformanceTests.Seed(agent, rule);

            var context = NewContext(prepare ?? (_ => { }));
            await new Middleware(_ => { Chained = true; return Task.CompletedTask; }, agent).InvokeAsync(context);

            return context;
        }

        private static AgentConfig Config()
            => new() { LicenseKey = LicenseKey, ApiUrl = "https://api.relintio.com/v1", Domain = "example.com" };

        private static HttpContext NewContext(Action<HttpRequest> prepare)
        {
            var context = new DefaultHttpContext();
            context.Request.Scheme = "https";
            context.Request.Host = new HostString("example.com");
            context.Request.Path = "/admin";
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.23");
            context.Response.Body = new System.IO.MemoryStream();
            prepare(context.Request);

            return context;
        }

        private static Func<HttpResponseMessage> Responds(HttpStatusCode status, string body)
            => () => new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            };

        /// <summary>Answers every outbound call, and keeps the bodies that were sent.</summary>
        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _reply;
            private readonly List<string> _bodies;

            public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> reply, List<string> bodies)
            {
                _reply = reply;
                _bodies = bodies;
            }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (request.Content is not null)
                {
                    lock (_bodies)
                    {
                        _bodies.Add(request.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult());
                    }
                }

                return await Task.FromResult(_reply(request));
            }
        }
    }
}
