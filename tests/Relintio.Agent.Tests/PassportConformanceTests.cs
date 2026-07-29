using System;
using System.IO;
using System.Text;
using System.Text.Json;

using Xunit;

namespace Relintio.Tests
{
    /// <summary>
    /// Conformance against contracts/passport-v2-vectors.json.
    ///
    /// The vectors are shared by all twelve SDKs. A failure here means this
    /// agent disagrees with the challenge server, which in production means
    /// every visitor who passed the challenge is then blocked by the agent,
    /// with nothing in any log to explain it.
    ///
    /// The file is read at run time rather than transcribed into constants
    /// here. Adding a vector is how a new edge case becomes binding on all
    /// twelve SDKs at once, and a copy living in this file would keep passing
    /// after the contract had moved underneath it.
    /// </summary>
    public class PassportConformanceTests
    {
        // Held for the lifetime of the fixture: JsonElement is a view into the
        // document's buffers and reading one after the document is collected is
        // undefined.
        private static readonly JsonDocument Document = JsonDocument.Parse(File.ReadAllBytes(VectorsPath()));

        private static readonly JsonElement V = Document.RootElement;

        private static readonly string Key = V.GetProperty("license_key").GetString()!;
        private static readonly string Ua = V.GetProperty("user_agent").GetString()!;
        private static readonly string Lang = V.GetProperty("accept_language").GetString()!;
        private static readonly long Now = V.GetProperty("now").GetInt64();

        /// <summary>
        /// Walks up looking for the file rather than counting ".." segments.
        /// The directory a test runs in differs between `dotnet test`, an IDE
        /// and the repo-wide conformance harness, and a fixed depth is only
        /// right for one of them. The build output directory is consulted too,
        /// for the runners that leave the working directory somewhere else
        /// entirely.
        /// </summary>
        private static string VectorsPath()
        {
            foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
            {
                for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                {
                    var candidate = Path.Combine(dir.FullName, "contracts", "passport-v2-vectors.json");
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }

            throw new FileNotFoundException(
                $"contracts/passport-v2-vectors.json not found at or above {Directory.GetCurrentDirectory()}");
        }

        [Fact]
        public void BindingMatchesVectors()
        {
            var i = 0;

            foreach (var c in V.GetProperty("binding").EnumerateArray())
            {
                var expect = c.GetProperty("expect").GetString();
                var got = Passport.Binding(
                    Key,
                    c.GetProperty("user_agent").GetString(),
                    c.GetProperty("accept_language").GetString());

                Assert.True(expect == got, $"binding[{i}] = {got}, want {expect}");
                i++;
            }
        }

        [Fact]
        public void MintMatchesVectors()
        {
            foreach (var c in V.GetProperty("mint").EnumerateArray())
            {
                var ttl = c.GetProperty("ttl").GetInt64();
                var expect = c.GetProperty("expect").GetString();
                var got = Passport.Mint(ttl, Key, Ua, Lang, Now);

                Assert.True(expect == got, $"mint with ttl {ttl} = {got}, want {expect}");
            }
        }

        /// <summary>
        /// Both directions matter equally. A passport that fails to verify locks
        /// out a visitor who did everything right; one that verifies when it
        /// should not is a bypass, which is what v2 was built to close.
        /// </summary>
        [Fact]
        public void VerifyMatchesVectors()
        {
            foreach (var c in V.GetProperty("verify").EnumerateArray())
            {
                var name = c.GetProperty("name").GetString();
                var expectValid = c.GetProperty("expect_valid").GetBoolean();

                var payload = Passport.Verify(c.GetProperty("token").GetString(), Key, Ua, Lang, Now);

                Assert.True(
                    (payload is not null) == expectValid,
                    $"vector \"{name}\": valid={payload is not null}, want {expectValid}");

                if (c.TryGetProperty("expect_ttl", out var expectTtl))
                {
                    Assert.True(
                        payload!.Ttl == expectTtl.GetInt64(),
                        $"vector \"{name}\": ttl={payload.Ttl}, want {expectTtl.GetInt64()}");
                }
            }
        }

        [Fact]
        public void SigningMatchesVectors()
        {
            var signing = V.GetProperty("signing");
            var expect = signing.GetProperty("expect").GetString();

            var got = Passport.SignRequest(
                Encoding.UTF8.GetBytes(signing.GetProperty("body").GetString()!),
                Key,
                signing.GetProperty("timestamp").GetInt64(),
                signing.GetProperty("nonce").GetString()!);

            Assert.True(expect == got, $"signature = {got}, want {expect}");
        }

        /// <summary>
        /// The vectors fix what this agent must agree with; this fixes what it
        /// must refuse. A passport is only worth anything while it is useless to
        /// anyone who did not earn it.
        /// </summary>
        [Fact]
        public void RoundTripIsBoundToTheClient()
        {
            var minted = Passport.Mint(3600, Key, Ua, Lang);

            Assert.True(Passport.Verify(minted, Key, Ua, Lang) is not null, "freshly minted passport did not verify");
            Assert.True(
                Passport.Verify(minted, Key, "curl/8.4.0", Lang) is null,
                "passport verified for a client it was not bound to");
        }

        /// <summary>
        /// The ttl arrives signed, so it is trusted; the clamp is there for the
        /// day an upstream bug mints a ten-year cookie nobody can revoke.
        /// </summary>
        [Fact]
        public void TtlIsClamped()
        {
            Assert.Equal(300L, Passport.ClampTtl(10));
            Assert.Equal(604800L, Passport.ClampTtl(99999999));
            Assert.Equal(86400L, Passport.ClampTtl(86400));
            Assert.Equal(86400L, Passport.ClampTtl(0));
        }
    }
}
