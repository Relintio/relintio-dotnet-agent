using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.Json;

using Xunit;

namespace Relintio.Tests
{
    /// <summary>
    /// Conformance against contracts/rule-conditions-v1.json.
    ///
    /// Rule matching is a contract held in twelve places, and it had drifted in
    /// most of them. This agent had no branch for the <c>header</c> type at all,
    /// so a <c>header_match</c> rule a customer authored in the dashboard
    /// reached the agent, matched nothing, scored zero and reported nothing —
    /// in silence. Its <c>equals</c> compared byte for byte while Java's folded
    /// case, so one dashboard rule holding an IPv6 address matched in one
    /// runtime and not the other. And an unrecognised condition fell through to
    /// a substring search, which is the worst of the three: the rule did
    /// something, just not what its author wrote.
    ///
    /// The file is read at run time rather than transcribed into constants here.
    /// Adding a vector is how a new edge case becomes binding on every SDK at
    /// once, and a copy living in this file would keep passing after the
    /// contract had moved underneath it.
    /// </summary>
    public class RuleConditionsConformanceTests
    {
        /// <summary>
        /// This agent evaluates <c>regex</c> with <c>System.Text.RegularExpressions</c>,
        /// so no vector is skipped here. The flag exists so that a skip is a
        /// deliberate, visible decision in the SDKs that cannot — never a silent
        /// pass.
        /// </summary>
        private const bool SupportsRegex = true;

        // Held for the lifetime of the fixture: JsonElement is a view into the
        // document's buffers and reading one after the document is collected is
        // undefined.
        private static readonly JsonDocument Document = JsonDocument.Parse(File.ReadAllBytes(ContractPath()));

        [Fact]
        public void EveryVectorMatchesTheContract()
        {
            var failures = new List<string>();
            var asserted = 0;
            var skipped = 0;

            foreach (var vector in Document.RootElement.GetProperty("vectors").EnumerateArray())
            {
                var name = vector.GetProperty("name").GetString();
                var rule = vector.GetProperty("rule");
                var request = vector.GetProperty("request");

                if (!SupportsRegex
                    && vector.TryGetProperty("skip_if_unsupported", out var skippable)
                    && skippable.GetBoolean())
                {
                    Console.WriteLine($"SKIP rule-conditions vector \"{name}\": no regex engine in this agent");
                    skipped++;

                    continue;
                }

                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (request.TryGetProperty("headers", out var supplied))
                {
                    foreach (var header in supplied.EnumerateObject())
                    {
                        headers[header.Name] = header.Value.GetString() ?? string.Empty;
                    }
                }

                var matched = Matches(
                    rule.GetProperty("type").GetString()!,
                    rule.GetProperty("pattern").GetString()!,
                    rule.GetProperty("condition").GetString()!,
                    Text(request, "ip"),
                    Text(request, "user_agent"),
                    Text(request, "path"),
                    headers);

                var expected = vector.GetProperty("matches").GetBoolean();
                if (matched != expected)
                {
                    failures.Add($"{name}: matched={matched}, want {expected}");
                }

                asserted++;
            }

            Console.WriteLine($"rule-conditions: {asserted} asserted, {skipped} skipped");

            Assert.True(asserted > 0, "the contract carries no vectors");
            Assert.True(failures.Count == 0, "vectors the agent disagrees with:\n  " + string.Join("\n  ", failures));
        }

        /// <summary>
        /// The failure the contract calls out by name. A <c>regex</c> that
        /// quietly becomes a substring search matches something other than what
        /// its author wrote — a longer path the anchors were meant to exclude,
        /// and never the alternation they were meant to include.
        /// </summary>
        [Fact]
        public void RegexIsEvaluatedAsARegexAndNotAsASubstring()
        {
            Assert.True(MatchesPath("^/admin$", "regex", "/admin"), "anchored pattern did not match its exact path");
            Assert.False(MatchesPath("^/admin$", "regex", "/administrator"), "anchored pattern matched a longer path");
            Assert.False(MatchesPath("^/admin$", "regex", "^/admin$"), "pattern was compared as a literal substring");

            Assert.True(
                Matches("user_agent", "(curl|wget)/", "regex", string.Empty, "wget/1.21", string.Empty, Empty),
                "alternation was not evaluated");
        }

        /// <summary>
        /// A pattern the author got wrong is a broken rule, never a broken
        /// request. An uncompilable expression is skipped rather than thrown out
        /// of the decision path, where the only thing to catch it would be the
        /// visitor.
        /// </summary>
        [Fact]
        public void AnInvalidRegexNeitherMatchesNorThrows()
        {
            Assert.False(MatchesPath("([unclosed", "regex", "([unclosed"), "an uncompilable pattern matched");
        }

        /// <summary>
        /// Fail closed. A type or condition this agent does not know contributes
        /// nothing, rather than falling back to a match: a rule that silently
        /// means something else is worse than one that does nothing.
        /// </summary>
        [Fact]
        public void UnknownTypesAndConditionsNeverMatch()
        {
            Assert.False(MatchesPath("/admin", "starts_with", "/admin"), "an unknown condition matched");
            Assert.False(
                Matches("cookie", "session", "contains", string.Empty, "session", "/", Empty),
                "an unknown type matched");
        }

        // ── driving the agent ────────────────────────────────────────────────

        private static readonly IReadOnlyDictionary<string, string> Empty = new Dictionary<string, string>();

        private static bool MatchesPath(string pattern, string condition, string path)
            => Matches("path", pattern, condition, string.Empty, string.Empty, path, Empty);

        /// <summary>
        /// Runs one rule through the real decision path rather than reaching for
        /// the matcher directly: the type dispatch is half of what these vectors
        /// are checking, and a test that called MatchValue would have passed
        /// throughout the years the <c>header</c> branch did not exist.
        /// </summary>
        private static bool Matches(
            string type,
            string pattern,
            string condition,
            string ip,
            string userAgent,
            string path,
            IReadOnlyDictionary<string, string> headers)
        {
            using var agent = new Agent(new AgentConfig { LicenseKey = "test_license_key" });

            Seed(agent, new WafRule { Type = type, Pattern = pattern, Condition = condition, Score = 100, Action = "block" });

            return agent.CheckRequest(ip, userAgent, path, headers).Score != 0;
        }

        /// <summary>
        /// Puts one rule in the cache the way a sync would. Reflection rather
        /// than a seam on the public type: a loader added for the benefit of a
        /// test is API a customer can then call, and the field it writes is the
        /// one the decision path actually reads.
        /// </summary>
        internal static void Seed(Agent agent, params WafRule[] rules)
        {
            var field = typeof(Agent).GetField("_rules", BindingFlags.Instance | BindingFlags.NonPublic)
                ?? throw new InvalidOperationException("the agent no longer holds its rules in a field named _rules");

            field.SetValue(agent, new List<WafRule>(rules));
        }

        /// <summary>A request field the vector left out is the absent case, not a failure.</summary>
        private static string Text(JsonElement request, string field)
            => request.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? string.Empty
                : string.Empty;

        /// <summary>
        /// Walks up looking for the file rather than counting ".." segments. The
        /// directory a test runs in differs between `dotnet test`, an IDE and
        /// the repo-wide harness, and a fixed depth is only right for one of
        /// them.
        /// </summary>
        private static string ContractPath()
        {
            foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
            {
                for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                {
                    var candidate = Path.Combine(dir.FullName, "contracts", "rule-conditions-v1.json");
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }

            throw new FileNotFoundException(
                $"contracts/rule-conditions-v1.json not found at or above {Directory.GetCurrentDirectory()}");
        }
    }
}
