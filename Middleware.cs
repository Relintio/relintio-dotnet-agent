using System;
using System.Text.Encodings.Web;
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

            // Skip security checks for internal challenge routes
            if (path == "/_relintio/challenge" || path == "/_relintio/verify")
            {
                await _next(context);
                return;
            }

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            var userAgent = context.Request.Headers["User-Agent"].ToString();

            var result = _agent.CheckRequest(ip, userAgent, path);
            _agent.QueueTelemetry(ip, userAgent, path, result);

            if (result.Action == "block")
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync("<!DOCTYPE html><html><head><title>Access Denied</title><style>body{background:#000;color:#fff;font-family:sans-serif;padding:50px;text-align:center;}</style></head><body><h1>403 Forbidden</h1><p>Request blocked by Relintio WAF protection.</p></body></html>");
                return;
            }

            if (result.Action == "challenge")
            {
                var challengeUrl = $"/_relintio/challenge?ref={UrlEncoder.Default.Encode(path)}";
                
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                context.Response.Headers.Append("X-Relintio-Action", "challenge");
                context.Response.Headers.Append("X-Relintio-Challenge-URL", challengeUrl);
                context.Response.ContentType = "text/html";
                
                await context.Response.WriteAsync($"<!DOCTYPE html><html><head><title>Security Challenge</title></head><body><script>window.location.href='{challengeUrl}';</script></body></html>");
                return;
            }

            await _next(context);
        }
    }
}
