using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecureApiDemo.Data;
using SecureApiDemo.Middleware;
using SecureApiDemo.Models;
using SecureApiDemo.Security;
using SecureApiDemo.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ─── PostgreSQL/SQL Server + ASP.NET Identity ───────────────────────────────────────────
builder.Services.AddDbContext<AppDbContext>(options =>
{
    var connectionString = builder.Configuration
        .GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Connection string not configured.");

    if (connectionString.StartsWith("postgresql://") ||
        connectionString.StartsWith("postgres://"))
    {
        // ✅ Handle postgresql:// URL format from Render
        var uri = new Uri(connectionString);
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 5432;
        var database = uri.AbsolutePath.TrimStart('/');
        var username = uri.UserInfo.Split(':')[0];
        var password = uri.UserInfo.Split(':')[1];

        var npgsql = $"Host={host};Port={port};Database={database};" +
                     $"Username={username};Password={password};" +
                     $"SSL Mode=Require;Trust Server Certificate=true";

        options.UseNpgsql(npgsql);
    }
    else if (connectionString.Contains("Host="))
    {
        // ✅ Handle Host= format (already converted)
        options.UseNpgsql(connectionString);
    }
    else
    {
        // ✅ SQL Server for local development
        options.UseSqlServer(connectionString);
    }
});
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.ClaimsIdentity.UserIdClaimType = JwtRegisteredClaimNames.Sub;
    options.ClaimsIdentity.UserNameClaimType = JwtRegisteredClaimNames.Sub;

    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 8;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// ─── JWT Authentication ───────────────────────────────────────────────────────
var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("JWT key not configured.");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero
    };
})
.AddCookie("Cookies", options =>
{
    // Cookie for SSO state management
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
})
;

// ─── Authorization Policies ───────────────────────────────────────────────────
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole("User", "Admin"));
});


// ─── Rate Limiting ────────────────────────────────────────────────────────────
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("fixed", o =>
    {
        o.PermitLimit = 100;
        o.Window = TimeSpan.FromMinutes(1);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 5;
    });

    options.AddFixedWindowLimiter("auth", o =>
    {
        o.PermitLimit = 5;
        o.Window = TimeSpan.FromMinutes(1);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 0;
    });

    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// ─── Services ─────────────────────────────────────────────────────────────────
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddSingleton<ISecretService, SecretService>();
builder.Services.AddSingleton<ITwoFactorService, TwoFactorService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "SecureApiDemo", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter your JWT token (without 'Bearer' prefix)"
    });
    c.AddSecurityRequirement(new()
    {
        {
            new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } },
            Array.Empty<string>()
        }
    });
});
// SSO Services
builder.Services.AddHttpClient();
builder.Services.AddScoped<ISsoService, SsoService>();

// Session for SSO state
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});



// TLS Configuration
builder.ConfigureTls();

// Zero Trust Health Check
builder.Services.AddHealthChecks()
    .AddCheck<ZeroTrustHealthCheck>("zero-trust");
// mTLS Client Factory (for Gateway → API calls)
builder.Services.AddSingleton<MtlsHttpClientFactory>();
var app = builder.Build();
// ─── Auto-create DB + seed roles ─────────────────────────────────────────────
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    try
    {
        // ✅ EnsureDeleted only in development — never in production!
        if (app.Environment.IsDevelopment())
            await db.Database.EnsureDeletedAsync();

        await db.Database.MigrateAsync();

        foreach (var role in new[] { "Admin", "User" })
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
    }
    catch (Exception ex)
    {
        var logger = scope.ServiceProvider
            .GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Migration failed: {Message}", ex.Message);
        throw;
    }
}

// ─── Middleware Pipeline (ORDER MATTERS) ──────────────────────────────────────
// 1. Swagger
app.UseSwagger();
app.UseSwaggerUI();

// 2. HTTPS redirect
app.UseHttpsRedirection();

// 3. TLS Security (HSTS)
app.UseTlsSecurity();

// 4. Session (for SSO)
app.UseSession();

// 5. Cryptographic Security (A02) — no auth needed
app.UseMiddleware<CryptographicSecurityMiddleware>();

// 6. Injection Protection (A03) — no auth needed
app.UseMiddleware<InjectionProtectionMiddleware>();

// 7. Security Logging — log all requests including unauthenticated
app.UseMiddleware<SecurityLoggingMiddleware>();

// 8. Rate Limiting — before auth to stop brute force
app.UseRateLimiter();

// 9. Authentication — establish identity
app.UseAuthentication();

// 10. Authorization — check permissions
app.UseAuthorization();

// 11. Access Control (A01) — AFTER auth so user is known
app.UseMiddleware<AccessControlMiddleware>();

// 12. OWASP Security Headers (A04, A05, A10) — AFTER auth
app.UseMiddleware<OwaspSecurityHeadersMiddleware>();

// 13. Zero Trust — AFTER auth so claims are available
app.UseMiddleware<ZeroTrustMiddleware>();

// 14. mTLS — AFTER auth
app.UseMiddleware<MtlsValidationMiddleware>();

// 15. Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'");
    await next();
});

// 16. Health checks + Controllers
app.MapHealthChecks("/health");
app.MapControllers();
app.Run();