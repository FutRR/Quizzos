using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MonAPIDotNet.Data;
using MonAPIDotNet.Keys;
using MonAPIDotNet.Middleware;
using MonAPIDotNet.Service;
using System.Reflection;
using System.Text.Json;

namespace MonAPIDotNet
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddDbContext<MyDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("MaBase")));
            builder.Services.AddIdentityCore<ApplicationUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<MyDbContext>();
            builder.Services.AddScoped<JwtService>();
            builder.Services.AddScoped<IUserService, UserService>();
            builder.Services.AddScoped<IQuestionService, QuestionService>();
            builder.Services.AddScoped<IQuizService, QuizService>();
            builder.Services.AddScoped<ITagService, TagService>();
            builder.Services.AddScoped<IImageUploadService, CloudinaryImageUploadService>();
            builder.Services.AddScoped<IQuizAttemptService, QuizAttemptService>();
            builder.Services.AddSignalR();
            builder.Services.AddScoped<IImpostorGameService, ImpostorGameService>();

            builder.Services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true; // Empêche l'accès JavaScript au cookie (protection XSS)
                options.Cookie.SecurePolicy = builder.Environment.IsProduction() ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;
                options.Cookie.SameSite = SameSiteMode.Lax; // Lax permet les requêtes cross-site pour les navigations
                //options.Cookie.Secure = true; // Le cookie est envoyé uniquement sur HTTPS
                // options.Cookie.SameSite = SameSiteMode.Strict; // Protection CSRF
                options.Cookie.Name = "RefreshToken"; // Nom du cookie
                options.Cookie.MaxAge = TimeSpan.FromDays(7); // Durée de vie du cookie
                options.LoginPath = "/login"; // Page de connexion
                options.LogoutPath = "/logout"; // Page de déconnexion
            });
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options => 
            {
                options.MapInboundClaims = false;

                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    RequireExpirationTime = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    IssuerSigningKey = new RsaSecurityKey(RsaKeyProvider.GetPrivateKey())
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = async context =>
                    {
                        var jwtService = context.HttpContext.RequestServices.GetRequiredService<JwtService>();
                        var validAudiences = jwtService.GetValidAudience();

                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtDebug");
                        logger.LogInformation("Valid audiences from DB: [{Audiences}]", string.Join(", ", validAudiences));

                        context.Options.TokenValidationParameters.ValidAudiences = validAudiences;

                        // Support pour SignalR : lire le token depuis la query string
                        var accessToken = context.Request.Query["access_token"];
                        var path = context.HttpContext.Request.Path;
                        if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/gamehub"))
                        {
                            context.Token = accessToken;
                        }
                    },
                    OnAuthenticationFailed = context =>
                    {
                        var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("JwtDebug");
                        logger.LogError(context.Exception, "JWT Authentication failed");
                        return Task.CompletedTask;
                    }
                };  
            });
            // Add authorization services
            builder.Services.AddAuthorization();

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("frontend", policy =>
                {
                    policy.WithOrigins("http://localhost:3000")
                          .AllowAnyHeader()
                          .AllowAnyMethod()
                          .AllowCredentials();
                });
            });

            builder.Services.AddControllers()
                .AddJsonOptions(options =>
                {
                    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                });
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c =>
            {

                // Configure JWT Bearer dans Swagger
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Name = "Authorization",
                    Type = SecuritySchemeType.Http,
                    Scheme = "Bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Description = "JWT Authorization header using the Bearer scheme."
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        new string[] {}
                    }
                });
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseMiddleware<ExceptionMiddleware>();
            app.UseHttpsRedirection();
            app.UseCors("frontend");
            app.UseMiddleware<CsrfMiddleware>();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapHub<MonAPIDotNet.Hubs.GameHub>("/gamehub");
            app.MapControllers();

            app.Run();
        }
    }
}
