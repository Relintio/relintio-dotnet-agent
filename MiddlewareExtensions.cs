using Microsoft.AspNetCore.Builder;

namespace Relintio
{
    public static class MiddlewareExtensions
    {
        public static IApplicationBuilder UseRelintio(this IApplicationBuilder builder, Agent agent)
        {
            return builder.UseMiddleware<Middleware>(agent);
        }
    }
}
