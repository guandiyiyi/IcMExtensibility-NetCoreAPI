namespace TodoApi
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Linq;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.AspNetCore.Authentication.JwtBearer;

    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddIcmUserJwtAuthentication(
            this AuthenticationBuilder authenticationBuilder,
            IcmJwtAuthenticationConfiguration config)
        {
            authenticationBuilder.AddJwtBearer(IcmJwtAuthenticationConfiguration.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = config.ToTokenValidationParameters();
                options.Events = new JwtBearerEvents() {
                    OnAuthenticationFailed = context =>
                    {
                        // do something to handle failure
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        ClaimsPrincipal claimsPrincipal = context.Principal;
                        string upn = config.ExtractUpn(claimsPrincipal.Claims.ToArray());
                        // set identity in context.HttpContext
                        context.HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(upn));
                        return Task.CompletedTask;
                    }
                };
            });

            return authenticationBuilder;
        }
    }
}
