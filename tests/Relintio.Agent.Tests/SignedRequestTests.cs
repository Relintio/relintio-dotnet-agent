using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace Relintio.Tests
{
    /// <summary>
    /// The ingest calls are signed on the wire, not just in the helper.
    ///
    /// Passport.SigningHeaders had a passing conformance test long before
    /// anything called it, so these assert against a real outbound request
    /// instead: a handler sitting where the socket would be receives the bytes
    /// the agent actually transmitted and re-derives the signature exactly as
    /// VerifyAgentSignature does. Anything that re-encodes the body between
    /// signing and sending shows up here as a mismatch.
    ///
    /// The basis string is spelled out rather than borrowed from Passport. A
    /// test that signed with the code it is checking would agree with the agent
    /// even when both disagree with the server, which is the only disagreement
    /// that costs anything.
    /// </summary>
    public class SignedRequestTests
    {
        private const string LicenseKey = "sk_live_test_key";

        /// <summary>One request as the transport saw it.</summary>
        private sealed record Capture(byte[] Body, string Timestamp, string Nonce, string Signature, string? ContentType);

        /// <summary>
        /// Stands in for the socket. Captures rather than asserts, so a failure
        /// surfaces as a named test failing rather than as an exception the
        /// agent's own fail-open catch would swallow on the telemetry path.
        /// </summary>
        private sealed class CapturingHandler : HttpMessageHandler
        {
            public ConcurrentQueue<Capture> Seen { get; } = new();

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var body = request.Content is null
                    ? Array.Empty<byte>()
                    : await request.Content.ReadAsByteArrayAsync(cancellationToken);

                // Snapshotted to strings here: the agent disposes the request as
                // soon as this returns, and a captured header collection would
                // outlive the message it belongs to.
                Seen.Enqueue(new Capture(
                    body,
                    Single(request, "X-Relintio-Timestamp"),
                    Single(request, "X-Relintio-Nonce"),
                    Single(request, "X-Relintio-Signature"),
                    request.Content?.Headers.ContentType?.MediaType));

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"rules\":[]}", Encoding.UTF8, "application/json"),
                };
            }

            private static string Single(HttpRequestMessage request, string name)
                => request.Headers.TryGetValues(name, out var values)
                    ? string.Join(",", values)
                    : string.Empty;
        }

        /// <summary>
        /// Mirrors the server's own check, down to the order it applies it in,
        /// so a divergence fails here rather than in production as a 401 nobody
        /// can reproduce locally.
        /// </summary>
        private static void AssertSigned(Capture got)
        {
            Assert.StartsWith("v1=", got.Signature, StringComparison.Ordinal);

            var provided = got.Signature[3..];
            Assert.Matches("^[a-f0-9]{64}$", provided);

            Assert.Matches("^[0-9]+$", got.Timestamp);

            // The server allows 300s of drift either way; anything near that
            // bound in a test means the header is built from something other
            // than now.
            var drift = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - long.Parse(got.Timestamp, CultureInfo.InvariantCulture);
            Assert.InRange(drift, -5L, 5L);

            Assert.InRange(got.Nonce.Length, 16, 128);
            // The server matches [A-Za-z0-9_-]+ before it looks at the
            // signature, so a standard-base64 nonce never gets as far as being
            // wrong.
            Assert.Matches("^[A-Za-z0-9_-]+$", got.Nonce);

            // Hash the body the transport received, not the one the agent thinks
            // it sent.
            var bodyHash = Convert.ToHexString(SHA256.HashData(got.Body)).ToLowerInvariant();
            var basis = $"v1:{got.Timestamp}:{got.Nonce}:{bodyHash}";
            var expected = Convert.ToHexString(
                HMACSHA256.HashData(Encoding.UTF8.GetBytes(LicenseKey), Encoding.UTF8.GetBytes(basis))).ToLowerInvariant();

            Assert.True(
                expected == provided,
                $"signature does not cover the transmitted bytes; body was {Encoding.UTF8.GetString(got.Body)}");
        }

        private static Agent AgentWith(CapturingHandler handler)
            => new(new AgentConfig { LicenseKey = LicenseKey, ApiUrl = "https://api.example.test/v1", Domain = "example.com" }, handler);

        private static Capture Next(CapturingHandler handler)
        {
            Assert.True(handler.Seen.TryDequeue(out var got), "no request reached the transport");

            return got!;
        }

        [Fact]
        public async Task SyncRulesIsSigned()
        {
            var handler = new CapturingHandler();
            using var agent = AgentWith(handler);

            await agent.SyncRulesAsync();

            var got = Next(handler);
            Assert.Equal("application/json", got.ContentType);
            AssertSigned(got);
        }

        [Fact]
        public async Task TelemetryIsSigned()
        {
            var handler = new CapturingHandler();
            using var agent = AgentWith(handler);

            // Called directly rather than through QueueTelemetry: that drains on
            // a background task, and a test racing it would flake.
            await agent.SendTelemetryAsync("203.0.113.7", "curl/8.4.0", "/login", new WafResult { Score = 90, Action = "block" });

            AssertSigned(Next(handler));
        }

        /// <summary>
        /// A signature is only single-use: the server burns the nonce, so two
        /// calls that reused one would leave the second rejected as a replay.
        /// </summary>
        [Fact]
        public async Task EachCallCarriesItsOwnNonce()
        {
            var handler = new CapturingHandler();
            using var agent = AgentWith(handler);

            await agent.SyncRulesAsync();
            await agent.SyncRulesAsync();

            var first = Next(handler);
            var second = Next(handler);

            Assert.NotEqual(first.Nonce, second.Nonce);
            AssertSigned(first);
            AssertSigned(second);
        }
    }
}
