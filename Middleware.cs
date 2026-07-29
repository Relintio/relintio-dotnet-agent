using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Relintio
{
    public class Middleware
    {
        private readonly RequestDelegate _next;
        private readonly Agent _agent;

        public Middleware(RequestDelegate next, Agent agent)
        {
            _next = next;
            _agent = agent;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;

            var ip = ResolveClientIp(context);
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            var headers = ReadHeaders(context.Request);

            var result = _agent.CheckRequest(ip, userAgent, path, headers);
            _agent.QueueTelemetry(ip, userAgent, path, result);

            if (result.Action == "block")
            {
                await Block(context);
                return;
            }

            if (result.Action == "challenge")
            {
                var outcome = await _agent.ChallengeAsync(AbsoluteUrl(context.Request, path), context.RequestAborted);

                if (outcome.Kind == ChallengeOutcome.ChallengeKind.Redirect)
                {
                    await Challenge(context, outcome.Url!);
                    return;
                }

                // The customer switched the challenge off and asked for these to
                // be blocked instead. That is a policy answer, not an outage,
                // and `allow` is the only fallback that lets the visitor past.
                if (outcome.Kind == ChallengeOutcome.ChallengeKind.Disabled)
                {
                    if (outcome.ShouldBlock)
                    {
                        await Block(context);
                        return;
                    }
                }
                else
                {
                    // No challenge was issued, so nothing was passed, and the
                    // engine's own verdict on this visitor still stands. Failing
                    // open here would make an unreachable token service the way
                    // through — the reference PHP agent, Node, Go and Ruby all
                    // block, and this SDK is not entitled to differ.
                    await Block(context);
                    return;
                }
            }

            await _next(context);
        }

        private static async Task Block(HttpContext context)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync("<!DOCTYPE html><html><head><title>Access Denied</title><style>body{background:#000;color:#fff;font-family:sans-serif;padding:50px;text-align:center;}</style></head><body><h1>403 Forbidden</h1><p>Request blocked by Relintio WAF protection.</p></body></html>");
        }

        /// <summary>
        /// A challenge is a <c>403</c> carrying <c>X-Relintio-Action</c> and
        /// <c>X-Relintio-Challenge-URL</c>, which is exactly what the React
        /// SDK's interceptor watches for: it opens the challenge overlay and
        /// replays the request that was refused.
        /// </summary>
        /// <remarks>
        /// The URL is the hosted challenge page and no longer
        /// <c>/_relintio/challenge</c>, which this SDK never served and used to
        /// skip — a redirect into a dead end. It is emitted through
        /// <see cref="HtmlEncoder"/> because it comes from the control plane and
        /// lands inside a script literal.
        /// </remarks>
        private static async Task Challenge(HttpContext context, string challengeUrl)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Relintio-Action"] = "challenge";
            context.Response.Headers["X-Relintio-Challenge-URL"] = challengeUrl;
            context.Response.ContentType = "text/html";

            var encoded = System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(challengeUrl);
            await context.Response.WriteAsync($"<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><script>window.location.href='{encoded}';</script></body></html>");
        }

        /// <summary>
        /// The client address, read the way the reference PHP agent reads it:
        /// <c>CF-Connecting-IP</c>, then the first entry of
        /// <c>X-Forwarded-For</c>, then <c>X-Real-IP</c>, then the socket.
        /// </summary>
        /// <remarks>
        /// This used to be the socket address alone, so behind any proxy, load
        /// balancer or CDN — which is nearly every production deployment — every
        /// <c>ip</c> rule saw the proxy rather than the visitor.
        ///
        /// The order is the security-relevant part, not a preference. Behind
        /// Cloudflare, <c>CF-Connecting-IP</c> is written by the edge while
        /// <c>X-Forwarded-For</c> has the caller's own value at the front, so
        /// reading the forwarded list first would hand a caller the client IP
        /// that every <c>ip</c> rule is keyed on.
        ///
        /// Each candidate has to parse as an address before it is accepted,
        /// which is what stops a junk or injected header from erasing the real
        /// one. Like every other SDK in the fleet, the forwarded headers are
        /// trusted unconditionally: an application reachable without going
        /// through your proxy will accept whatever a caller claims, so terminate
        /// that at the proxy or keep the container off the public network.
        /// </remarks>
        private static string ResolveClientIp(HttpContext context)
        {
            foreach (var name in new[] { "CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP" })
            {
                var supplied = context.Request.Headers[name].ToString();
                if (string.IsNullOrWhiteSpace(supplied))
                {
                    continue;
                }

                var first = supplied.Split(',')[0].Trim();
                if (IPAddress.TryParse(first, out var parsed))
                {
                    return parsed.ToString();
                }
            }

            return context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        }

        /// <summary>
        /// Every request header, so a <c>header</c> rule has something to match
        /// against. A repeated name is joined the way HTTP itself defines it,
        /// rather than reduced to its first value — a scanner that puts its
        /// signature in the second copy is exactly the traffic that type exists
        /// to catch.
        /// </summary>
        private static IReadOnlyDictionary<string, string> ReadHeaders(HttpRequest request)
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var header in request.Headers)
            {
                headers[header.Key] = string.Join(", ", header.Value.ToArray());
            }

            return headers;
        }

        /// <summary>
        /// Where the visitor is sent back to once they pass. The control plane
        /// rejects anything that is not an absolute http(s) URL, and the query
        /// string is left off deliberately — it is the part most likely to carry
        /// something that should not travel through a redirect.
        /// </summary>
        private static string AbsoluteUrl(HttpRequest request, string path)
        {
            var scheme = string.IsNullOrEmpty(request.Scheme) ? "https" : request.Scheme;
            var host = request.Host.HasValue ? request.Host.Value : "localhost";

            return $"{scheme}://{host}{(string.IsNullOrEmpty(path) ? "/" : path)}";
        }
    }
}
