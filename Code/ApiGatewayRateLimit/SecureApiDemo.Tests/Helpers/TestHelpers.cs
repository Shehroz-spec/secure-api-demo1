using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SecureApiDemo.Data;
using SecureApiDemo.Models;

namespace SecureApiDemo.Tests.Helpers;

/// <summary>
/// Shared test helpers and factory methods used across all test classes.
/// </summary>
public static class TestHelpers
{
    // ── Configuration ─────────────────────────────────────────────────────────
    public static IConfiguration BuildTestConfiguration() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"]                    = "ThisIsAVerySecretKeyForJwtToken123!",
                ["Jwt:Issuer"]                 = "SecureApiDemo",
                ["Jwt:Audience"]               = "SecureApiDemoUsers",
                ["Jwt:AccessTokenExpiryMinutes"] = "60",
                ["Jwt:RefreshTokenExpiryDays"] = "7",
                ["TwoFactor:AppName"]          = "SecureApiDemo"
            })
            .Build();

    // ── In-Memory DbContext ───────────────────────────────────────────────────
    public static AppDbContext BuildInMemoryDbContext(string? dbName = null)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(dbName ?? Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(options);
    }

    // ── UserManager ───────────────────────────────────────────────────────────
    public static UserManager<ApplicationUser> BuildUserManager(AppDbContext db)
    {
        var store   = new UserStore<ApplicationUser>(db);
        var options = Options.Create(new IdentityOptions
        {
            Password = { RequireDigit = true, RequiredLength = 8,
                         RequireLowercase = true, RequireUppercase = true,
                         RequireNonAlphanumeric = false },
            Lockout  = { MaxFailedAccessAttempts = 5,
                         DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15) },
            User     = { RequireUniqueEmail = true }
        });

        var passwordHasher  = new PasswordHasher<ApplicationUser>();
        var userValidators  = new List<IUserValidator<ApplicationUser>> { new UserValidator<ApplicationUser>() };
        var passValidators  = new List<IPasswordValidator<ApplicationUser>> { new PasswordValidator<ApplicationUser>() };
        var keyNormalizer   = new UpperInvariantLookupNormalizer();
        var errors          = new IdentityErrorDescriber();
        var logger          = new NullLogger<UserManager<ApplicationUser>>();

        return new UserManager<ApplicationUser>(
            store, options, passwordHasher,
            userValidators, passValidators,
            keyNormalizer, errors, null!, logger);
    }

    // ── RoleManager ───────────────────────────────────────────────────────────
    public static RoleManager<IdentityRole> BuildRoleManager(AppDbContext db)
    {
        var store          = new RoleStore<IdentityRole>(db);
        var roleValidators = new List<IRoleValidator<IdentityRole>> { new RoleValidator<IdentityRole>() };
        var keyNormalizer  = new UpperInvariantLookupNormalizer();
        var errors         = new IdentityErrorDescriber();
        var logger         = new NullLogger<RoleManager<IdentityRole>>();

        return new RoleManager<IdentityRole>(
            store, roleValidators, keyNormalizer, errors, logger);
    }

    // ── Seed Test User ────────────────────────────────────────────────────────
    public static async Task<ApplicationUser> SeedUserAsync(
        UserManager<ApplicationUser>  userManager,
        RoleManager<IdentityRole>     roleManager,
        string username  = "alice",
        string email     = "alice@test.com",
        string password  = "Password123!",
        string role      = "User")
    {
        // Seed role
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));

        // Seed user
        var user = new ApplicationUser
        {
            UserName = username,
            Email    = email,
        };

        await userManager.CreateAsync(user, password);
        await userManager.AddToRoleAsync(user, role);

        return user;
    }

    // ── Build Mock Logger ─────────────────────────────────────────────────────
    public static Mock<ILogger<T>> BuildMockLogger<T>() => new();
}
