using ApiGateway.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Ocelot.Cache.CacheManager;
using Serilog;
using System.Text;

// ─── Serilog Setup ────────────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console(outputTemplate:
        "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/gateway-.log",
        rollingInterval:        RollingInterval.Day,
        retainedFileCountLimit: 7,
        outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();
Console.WriteLine("Current Directory: " + Directory.GetCurrentDirectory());
Console.WriteLine("ocelot.json exists: " + File.Exists("ocelot.json"));
Console.WriteLine("ocelot.json full path: " + Path.GetFullPath("ocelot.json"));
// ─── Load Ocelot Config ───────────────────────────────────────────────────────
builder.Configuration
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("ocelot.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables();
Console.WriteLine("Base Directory: " + AppContext.BaseDirectory);
Console.WriteLine("ocelot.json exists: " +
    File.Exists(Path.Combine(AppContext.BaseDirectory, "ocelot.json")));
// ─── JWT Authentication (Gateway validates tokens before routing) ─────────────
var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("JWT key not configured.");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer              = builder.Configuration["Jwt:Issuer"],
            ValidAudience            = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey         = new SymmetricSecurityKey(
                                           Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew                = TimeSpan.Zero
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                Log.Warning("Gateway JWT auth failed: {Error}", ctx.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                Log.Information("Gateway JWT validated for: {User}",
                    ctx.Principal?.Identity?.Name);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

// ─── Ocelot + Response Caching ────────────────────────────────────────────────
builder.Services
    .AddOcelot(builder.Configuration)
    .AddCacheManager(x => x.WithDictionaryHandle());

// ─── CORS ─────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("GatewayPolicy", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

var app = builder.Build();

// ─── Middleware Pipeline ──────────────────────────────────────────────────────
app.UseSerilogRequestLogging(options =>
{
    options.MessageTemplate =
        "Gateway: {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000}ms";
});

app.UseCors("GatewayPolicy");

app.UseMiddleware<RequestTransformationMiddleware>();
app.UseMiddleware<GatewayLoggingMiddleware>();

app.UseAuthentication();
app.UseAuthorization();

// ✅ Ocelot must be absolute last — no app.Run() after
await app.UseOcelot();
await app.RunAsync();