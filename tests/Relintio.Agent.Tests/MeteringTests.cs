using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace Relintio.Tests
{
    /// <summary>
    /// The two halves of the metering contract, in this runtime.
    ///
    /// One: an allowed request is sampled, at the one rate the whole fleet uses.
    /// The platform multiplies a reported ALLOW back up by
    /// UsageMeterService::ALLOW_SAMPLE_RATE, so an agent reporting all of them
    /// inflates the customer's meter a hundredfold, and an agent reporting none
    /// of them leaves their dashboard showing no clean traffic at all.
    ///
    /// Two: nothing a control plane can answer with may leave this agent holding
    /// an empty ruleset. `quota_exceeded` used to do exactly that — a billing
    /// state switched off a customer's protection — and the shape of that defect
    /// was never the status string. It was that any 200 body deserialising into
    /// a SyncResponse replaced the policy, and an absent `rules` deserialised to
    /// an empty list.
    /// </summary>
    public class MeteringTests
    {
        private const string LicenseKey = "sk_live_test_key";

        private const string Policy =
            "{\"status\":\"success\",\"rules\":[{\"type\":\"path\",\"pattern\":\"/admin\"," +
            "\"condition\":\"contains\",\"score\":60,\"action\":\"challenge\"}]}";

        /// <summary>Answers every call with whatever <see cref="Body"/> currently holds.</summary>
        private sealed class FixedHandler : HttpMessageHandler
        {
            public string Body { get; set; } = Policy;

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(Body, Encoding.UTF8, "application/json"),
                });
        }

        [Fact]
        public void TheAllowSampleRateIsOnePercent()
        {
            // The literal is the point: it has to match
            // UsageMeterService::ALLOW_SAMPLE_RATE on the platform, and the
            // platform cannot read this file to find out.
            Assert.Equal(0.01, Agent.AllowSampleRate);
        }

        [Fact]
        public void OnlyAllowedRequestsAreSampled()
        {
            // Blocks, challenges, decoys and slows are the security record. The
            // platform counts them at face value, so every one of them is
            // reported.
            foreach (var action in new[] { "block", "challenge", "decoy", "slow", "BLOCK" })
            {
                for (var i = 0; i < 50; i++)
                {
                    Assert.True(Agent.ReportsAction(action), $"a {action} was sampled out; only allows may be");
                }
            }

            // And an allow is not reported every time. At 1% over 2000 draws the
            // odds of this failing on a correct implementation are nil.
            var reported = 0;
            for (var i = 0; i < 2000; i++)
            {
                if (Agent.ReportsAction("allow"))
                {
                    reported++;
                }
            }

            Assert.NotEqual(2000, reported);
            Assert.True(reported < 400, $"{reported} of 2000 allows reported; the rate is far above 1%");
        }

        [Fact]
        public async Task AnUnrecognisedVerifyResponseKeepsTheCachedPolicy()
        {
            var handler = new FixedHandler();
            using var agent = new Agent(
                new AgentConfig { LicenseKey = LicenseKey, ApiUrl = "https://api.example.test/v1", Domain = "example.com" },
                handler);

            Assert.True(await Sync(agent), "a well-formed ruleset was not accepted");
            Assert.Equal(1, Rules(agent).Count);

            // Every shape the control plane can answer 200 with that is not a
            // policy. The removed `quota_exceeded` is one of them, and is
            // deliberately still exercised: an old deployment may still emit it,
            // and it must now be as inert as any other word this agent does not
            // know.
            foreach (var unrecognised in new[]
                     {
                         "{\"status\":\"quota_exceeded\"}",
                         "{\"status\":\"something_new\"}",
                         "{}",
                         "{\"error\":\"internal\"}",
                         "{\"rules\":null}",
                     })
            {
                handler.Body = unrecognised;

                Assert.True(!await Sync(agent), $"{unrecognised} was accepted as a policy");
                Assert.True(
                    Rules(agent).Count == 1,
                    $"{unrecognised} cleared the cache; the last good policy must stay in force");
            }

            // An explicit empty array is a real, empty policy, and is applied.
            // Without this the guard above could be satisfied by an agent that
            // never accepts a change at all.
            handler.Body = "{\"status\":\"success\",\"rules\":[]}";

            Assert.True(await Sync(agent), "an explicit empty ruleset was rejected");
            Assert.Equal(0, Rules(agent).Count);
        }

        private static async Task<bool> Sync(Agent agent)
        {
            var method = typeof(Agent).GetMethod("SyncRulesInternalAsync", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.True(method is not null, "SyncRulesInternalAsync is gone; find where the sync moved");

            return await (Task<bool>)method!.Invoke(agent, new object?[] { CancellationToken.None })!;
        }

        private static List<WafRule> Rules(Agent agent)
        {
            var field = typeof(Agent).GetField("_rules", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.True(field is not null, "_rules is gone; find where the cache moved");

            return (List<WafRule>)field!.GetValue(agent)!;
        }
    }
}
