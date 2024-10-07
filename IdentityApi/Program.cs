
using IdentityApi.Data;
using IdentityApi.Extensions;
using Microsoft.EntityFrameworkCore;

namespace IdentityApi
{
    public class Program
    {
        public async static Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            builder.Services.AddDbContext<IdentityContext>(options =>
            options.UseSqlite(builder.Configuration.GetConnectionString("IdentityConnection")));

            builder.Services.AddApplicationServices(builder.Configuration);
            builder.Services.AddIdentityServices(builder.Configuration);

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("AllowAll",
                    builder =>
                    {
                        builder.AllowAnyOrigin()
                               .AllowAnyMethod()
                               .AllowAnyHeader()
                               .WithExposedHeaders("Location"); // Expose any headers if necessary
                    });
            });

            var app = builder.Build();

            #region update db
            using  var scope = app.Services.CreateScope();
            var services = scope.ServiceProvider;
            var LoggerFactory = services.GetRequiredService<ILoggerFactory>();

            try
            {
                //Ask CLR To Create Object From ApplicationDbContext Explicitly
                var IdentityContext = services.GetRequiredService<IdentityContext>();
                //var IdentityDbContext = services.GetRequiredService<AppIdentityDbContext>();
                //var UserManager = services.GetRequiredService<UserManager<User>>();

                await IdentityContext.Database.MigrateAsync();
                //await IdentityDbContext.Database.MigrateAsync();

                //await ApplicationContextSeed.SeedAsync(DbContext, LoggerFactory);
                //await AppIdentityDbContextSeeding.SeedUserAsync(UserManager);

            }
            catch (Exception ex)
            {
                var logger = LoggerFactory.CreateLogger<Program>();
                logger.LogError(ex, "An Error Occurred While Updating Database");
            }

            #endregion

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();

            app.UseCors("AllowAll");
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
