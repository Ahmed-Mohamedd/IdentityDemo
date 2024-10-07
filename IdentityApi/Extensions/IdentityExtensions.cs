using IdentityApi.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace IdentityApi.Extensions
{
    public static class IdentityExtensions
    {
        public static IServiceCollection AddIdentityServices(this IServiceCollection services , IConfiguration configuration)
        {

            services.AddIdentity<IdentityUser, IdentityRole>(options =>
            {
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Lockout duration
                options.Lockout.MaxFailedAccessAttempts = 5; // Number of failed attempts allowed
                options.Lockout.AllowedForNewUsers = true; // Lockout n
                options.SignIn.RequireConfirmedEmail = true;    
            }).AddEntityFrameworkStores<IdentityContext>()
            .AddDefaultTokenProviders();

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddFacebook(facebookOptions =>
                {
                    facebookOptions.AppId = configuration["FacebookAuth:AppId"];
                    facebookOptions.AppSecret = configuration["FacebookAuth:AppSecret"];
                    facebookOptions.SaveTokens = true;
                })
                .AddMicrosoftAccount(microsoftOptions =>
                {
                    microsoftOptions.ClientId = configuration["MicrosoftAuth:ClientID"];
                    microsoftOptions.ClientSecret = configuration["MicrosoftAuth:ClientSecret"];
                    microsoftOptions.SaveTokens = true;
                })
                .AddGoogle(options =>
                {
                    options.ClientId = configuration["OAuthClient:ClientId"];
                    options.ClientSecret = configuration["OAuthClient:ClientSecret"];
                })
              .AddJwtBearer(options =>
              {
                  options.RequireHttpsMetadata=false;
                  options.SaveToken=false;
                  options.TokenValidationParameters = new TokenValidationParameters
                  {
                      ValidateIssuerSigningKey = true,
                      ValidateAudience=true,
                      ValidateIssuer=true,
                      ValidateLifetime=true,
                      ValidIssuer=configuration["JWT:Issuer"],
                      ValidAudience=configuration["JWT:Audience"],
                      IssuerSigningKey= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]))

                  };
              });


            return services;
        }
    }
}
