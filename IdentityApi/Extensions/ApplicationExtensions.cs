using IdentityApi.Helpers;
using IdentityApi.Services;
using IdentityApi.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace IdentityApi.Extensions
{
    public static class ApplicationExtensions
    {
        public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Configure token lifespan
            services.Configure<DataProtectionTokenProviderOptions>(options =>
            {
                // Set token lifespan to 2 hours
                options.TokenLifespan = TimeSpan.FromHours(12);
            });
            services.AddTransient<IEmailService, EmailService>();
            services.AddScoped<ITokenProvider, TokenProvider>();
            services.Configure<JWT>(configuration.GetSection("JWT"));//Add configuration For JWTSetting Class
            services.Configure<EmailSetting>(configuration.GetSection("EmailSettings"));

            return services;
        }
    }
}
