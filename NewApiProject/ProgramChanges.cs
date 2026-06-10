// ─────────────────────────────────────────────────────────────────────────────
// CHANGES TO ADD TO Program.cs FOR SSO SUPPORT
// Add these sections to your existing Program.cs
// ─────────────────────────────────────────────────────────────────────────────

// ── Step 1: Add NuGet Package ─────────────────────────────────────────────────
// Run in terminal:
// dotnet add package Microsoft.Identity.Web --version 3.3.0

// ── Step 2: Add Using Statements ─────────────────────────────────────────────
using Microsoft.Identity.Web;

// ── Step 3: Add HttpClient (needed for Microsoft Graph calls) ────────────────
// Add BEFORE builder.Build():
builder.Services.AddHttpClient();

// ── Step 4: Add SSO Service ───────────────────────────────────────────────────
// Add BEFORE builder.Build():
builder.Services.AddScoped<ISsoService, SsoService>();

// ── Step 5: Add Cookie Auth (needed for SSO state management) ────────────────
// Add BEFORE builder.Build() AFTER AddAuthentication:
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // ... your existing JWT config ...
})
.AddCookie("Cookies", options =>
{
    // Cookie for SSO state management
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
});

// ── Step 6: Add Session (for SSO state) ──────────────────────────────────────
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout        = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly    = true;
    options.Cookie.IsEssential = true;
});

// ── Step 7: Add Session to Pipeline ──────────────────────────────────────────
// Add AFTER app = builder.Build() and BEFORE UseAuthentication:
app.UseSession();

// ─────────────────────────────────────────────────────────────────────────────
// COMPLETE Program.cs SERVICES SECTION (replace your existing)
// ─────────────────────────────────────────────────────────────────────────────

/*
// SQL Server + Identity
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentityCore<ApplicationUser>(options => { ... })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// JWT + Cookie Auth (both schemes)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options => { ... })
.AddCookie("Cookies", options =>
{
    options.Cookie.HttpOnly     = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ExpireTimeSpan      = TimeSpan.FromMinutes(10);
});

// HttpClient for Microsoft Graph
builder.Services.AddHttpClient();

// Session for SSO state
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout        = TimeSpan.FromMinutes(10);
    options.Cookie.HttpOnly    = true;
    options.Cookie.IsEssential = true;
});

// Services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<ISsoService, SsoService>();
builder.Services.AddSingleton<ISecretService, SecretService>();
builder.Services.AddSingleton<ITwoFactorService, TwoFactorService>();
*/
