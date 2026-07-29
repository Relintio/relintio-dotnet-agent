using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// Lives in `Relintio` alongside the rest of the SDK rather than in a
// `Relintio.Agent` namespace of its own. The `Relintio.Agent` *type* shadows a
// namespace of the same name for every consumer that can see both, so a
// `Relintio.Agent.Passport` is not merely awkward to reference — it cannot be
// named at all, not even fully qualified, which is why nothing in this SDK
// called it.
namespace Relintio
{
    /// <summary>
    /// Relintio agent protocol v2 — passport and request signing.
    ///
    /// Implements contracts/agent-protocol-v2.md and is verified against
    /// contracts/passport-v2-vectors.json by the shared conformance suite.
    ///
    /// Nothing here touches the network: the edge must keep deciding when the
    /// control plane is unreachable, so a passport is verifiable with the
    /// licence key alone.
    /// </summary>
    public static class Passport
    {
        /// <summary>Cookie an agent sets once a visitor has passed.</summary>
        public const string Cookie = "relintio_passport";

        /// <summary>Absorbs clock drift between the challenge server and this agent.</summary>
        public const long ClockSkewSeconds = 60;

        private const long MinTtl = 300;
        private const long MaxTtl = 604800;

        /// <summary>
        /// Decoded body of a v2 token. Unknown fields are ignored rather than
        /// rejected — that is the extension point for a future revision.
        /// </summary>
        public sealed class Payload
        {
            public long V { get; init; }
            public long Exp { get; init; }
            public string B { get; init; } = string.Empty;
            public long? Ttl { get; init; }
            public string? Jti { get; init; }
        }

        /// <summary>
        /// The client identity a passport is tied to.
        ///
        /// <paramref name="userAgent"/> and <paramref name="acceptLanguage"/>
        /// must be the raw header values as received. Trimming or lowercasing
        /// them here makes this agent disagree with the challenge server, which
        /// locks every visitor out.
        /// </summary>
        public static string Binding(string licenseKey, string? userAgent, string? acceptLanguage)
        {
            var joined = string.Join("|", licenseKey ?? string.Empty, userAgent ?? string.Empty, acceptLanguage ?? string.Empty);
            var digest = SHA256.HashData(Encoding.UTF8.GetBytes(joined));

            return Convert.ToHexString(digest).ToLowerInvariant()[..16];
        }

        /// <summary>
        /// Verify a v2 pass token or passport cookie. Pass <paramref name="now"/>
        /// as 0 to use the wall clock.
        /// </summary>
        /// <returns>The payload, or null when malformed, forged, expired, or bound to another client.</returns>
        public static Payload? Verify(string? value, string licenseKey, string? userAgent, string? acceptLanguage, long now = 0)
        {
            if (string.IsNullOrEmpty(value) || !value.StartsWith("v2.", StringComparison.Ordinal))
            {
                return null;
            }

            var parts = value.Split('.');
            if (parts.Length != 3)
            {
                return null;
            }

            var raw = Base64UrlDecode(parts[1]);
            var signature = Base64UrlDecode(parts[2]);
            if (raw is null || signature is null || raw.Length == 0 || signature.Length == 0)
            {
                return null;
            }

            var expected = Hmac(licenseKey, raw);
            if (!CryptographicOperations.FixedTimeEquals(expected, signature))
            {
                return null;
            }

            Payload payload;
            try
            {
                using var document = JsonDocument.Parse(raw);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }

                payload = new Payload
                {
                    V = root.TryGetProperty("v", out var v) && v.TryGetInt64(out var vv) ? vv : 0,
                    Exp = root.TryGetProperty("exp", out var e) && e.TryGetInt64(out var ee) ? ee : 0,
                    B = root.TryGetProperty("b", out var b) ? b.GetString() ?? string.Empty : string.Empty,
                    Ttl = root.TryGetProperty("ttl", out var t) && t.TryGetInt64(out var tt) ? tt : null,
                    Jti = root.TryGetProperty("jti", out var j) ? j.GetString() : null,
                };
            }
            catch (JsonException)
            {
                return null;
            }

            var moment = now == 0 ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() : now;
            if (payload.Exp + ClockSkewSeconds < moment)
            {
                return null;
            }

            var bound = Encoding.UTF8.GetBytes(payload.B);
            var mine = Encoding.UTF8.GetBytes(Binding(licenseKey, userAgent, acceptLanguage));
            if (!CryptographicOperations.FixedTimeEquals(bound, mine))
            {
                return null;
            }

            return payload;
        }

        /// <summary>
        /// The cookie value this agent sets after a successful exchange. Pass
        /// <paramref name="now"/> as 0 to use the wall clock.
        /// </summary>
        public static string Mint(long ttl, string licenseKey, string? userAgent, string? acceptLanguage, long now = 0)
        {
            var moment = now == 0 ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() : now;

            // Hand-built so field order and separators are fixed: the signature
            // covers these exact bytes, and a serializer's ordering is not part
            // of the contract.
            var raw = string.Format(
                CultureInfo.InvariantCulture,
                "{{\"v\":2,\"exp\":{0},\"b\":\"{1}\"}}",
                moment + ttl,
                Binding(licenseKey, userAgent, acceptLanguage));

            var rawBytes = Encoding.UTF8.GetBytes(raw);

            return "v2." + Base64UrlEncode(rawBytes) + "." + Base64UrlEncode(Hmac(licenseKey, rawBytes));
        }

        /// <summary>Keep a signed-but-implausible ttl inside sane bounds.</summary>
        public static long ClampTtl(long ttl)
        {
            var value = ttl <= 0 ? 86400 : ttl;

            return Math.Max(MinTtl, Math.Min(value, MaxTtl));
        }

        /// <summary>
        /// Signature for one ingest call. <paramref name="body"/> must be the
        /// exact bytes that will be transmitted; hashing an object and letting
        /// an HTTP client re-serialise it yields a signature the server cannot
        /// reproduce.
        /// </summary>
        public static string SignRequest(byte[] body, string licenseKey, long timestamp, string nonce)
        {
            var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
            var basis = string.Format(CultureInfo.InvariantCulture, "v1:{0}:{1}:{2}", timestamp, nonce, bodyHash);

            return Convert.ToHexString(Hmac(licenseKey, Encoding.UTF8.GetBytes(basis))).ToLowerInvariant();
        }

        /// <summary>Ready-made headers for an ingest call, with a fresh nonce per request.</summary>
        public static IDictionary<string, string> SigningHeaders(byte[] body, string licenseKey)
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var nonce = Base64UrlEncode(RandomNumberGenerator.GetBytes(18));

            return new Dictionary<string, string>
            {
                ["X-Relintio-Timestamp"] = timestamp.ToString(CultureInfo.InvariantCulture),
                ["X-Relintio-Nonce"] = nonce,
                ["X-Relintio-Signature"] = "v1=" + SignRequest(body, licenseKey, timestamp, nonce),
            };
        }

        private static byte[] Hmac(string key, byte[] message)
            => HMACSHA256.HashData(Encoding.UTF8.GetBytes(key ?? string.Empty), message);

        private static string Base64UrlEncode(byte[] raw)
            => Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        private static byte[]? Base64UrlDecode(string value)
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - (padded.Length % 4)) % 4);

            try
            {
                return Convert.FromBase64String(padded);
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }
}
