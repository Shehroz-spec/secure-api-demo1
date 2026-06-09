using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using SecureApiDemo.Tests.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Xunit;

namespace SecureApiDemo.Tests.Services;

public class TokenServiceTests
{
    private readonly TokenService _tokenService;
    private readonly ApplicationUser _testUser;

    public TokenServiceTests()
    {
        var config  = TestHelpers.BuildTestConfiguration();
        var db      = TestHelpers.BuildInMemoryDbContext();
        var logger  = new NullLogger<TokenService>();

        _tokenService = new TokenService(config, db, logger);

        _testUser = new ApplicationUser
        {
            Id               = Guid.NewGuid().ToString(),
            UserName         = "alice",
            Email            = "alice@test.com",
            TwoFactorEnabled = false
        };
    }

    // ── GenerateAccessToken Tests ─────────────────────────────────────────────

    [Fact]
    public void GenerateAccessToken_ValidUser_ReturnsNonEmptyToken()
    {
        // Act
        var token = _tokenService.GenerateAccessToken(_testUser, "User");

        // Assert
        token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GenerateAccessToken_ValidUser_ReturnsValidJwtFormat()
    {
        // Act
        var token = _tokenService.GenerateAccessToken(_testUser, "User");

        // Assert — JWT has 3 parts separated by dots
        var parts = token.Split('.');
        parts.Should().HaveCount(3);
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectClaims()
    {
        // Act
        var token   = _tokenService.GenerateAccessToken(_testUser, "Admin");
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        // Assert
        jwt.Claims.Should().Contain(c => c.Type == "role" && c.Value == "Admin");
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Sub && c.Value == "alice");
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email && c.Value == "alice@test.com");
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectIssuerAndAudience()
    {
        // Act
        var token   = _tokenService.GenerateAccessToken(_testUser, "User");
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        // Assert
        jwt.Issuer.Should().Be("SecureApiDemo");
        jwt.Audiences.Should().Contain("SecureApiDemoUsers");
    }

    [Fact]
    public void GenerateAccessToken_TokenExpiresInOneHour()
    {
        // Act
        var token   = _tokenService.GenerateAccessToken(_testUser, "User");
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        // Assert — expires roughly 60 minutes from now (allow 5s tolerance)
        jwt.ValidTo.Should().BeCloseTo(DateTime.UtcNow.AddMinutes(60), TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("User")]
    public void GenerateAccessToken_DifferentRoles_ContainsCorrectRole(string role)
    {
        // Act
        var token   = _tokenService.GenerateAccessToken(_testUser, role);
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        // Assert
        jwt.Claims.Should().Contain(c => c.Type == "role" && c.Value == role);
    }

    [Fact]
    public void GenerateAccessToken_TwoFactorEnabled_ReflectedInClaim()
    {
        // Arrange
        _testUser.TwoFactorEnabled = true;

        // Act
        var token   = _tokenService.GenerateAccessToken(_testUser, "User");
        var handler = new JwtSecurityTokenHandler();
        var jwt     = handler.ReadJwtToken(token);

        // Assert
        jwt.Claims.Should().Contain(c => c.Type == "2fa_verified" && c.Value == "true");
    }

    // ── GenerateRefreshToken Tests ────────────────────────────────────────────

    [Fact]
    public async Task GenerateRefreshTokenAsync_ReturnsNonEmptyToken()
    {
        // Act
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);

        // Assert
        refreshToken.Token.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GenerateRefreshTokenAsync_TokenExpiresInSevenDays()
    {
        // Act
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);

        // Assert
        refreshToken.ExpiresAt.Should().BeCloseTo(
            DateTime.UtcNow.AddDays(7), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task GenerateRefreshTokenAsync_IsActiveByDefault()
    {
        // Act
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);

        // Assert
        refreshToken.IsActive.Should().BeTrue();
        refreshToken.IsRevoked.Should().BeFalse();
        refreshToken.IsExpired.Should().BeFalse();
    }

    [Fact]
    public async Task GenerateRefreshTokenAsync_TwoTokens_AreUnique()
    {
        // Act
        var token1 = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);
        var token2 = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);

        // Assert
        token1.Token.Should().NotBe(token2.Token);
    }

    // ── RevokeRefreshToken Tests ──────────────────────────────────────────────

    [Fact]
    public async Task RevokeRefreshTokenAsync_ValidToken_SetsRevokedAt()
    {
        // Arrange
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(_testUser.Id);

        // Act
        await _tokenService.RevokeRefreshTokenAsync(refreshToken.Token);

        // Assert
        refreshToken.RevokedAt.Should().NotBeNull();
        refreshToken.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task RevokeRefreshTokenAsync_NonExistentToken_DoesNotThrow()
    {
        // Act & Assert — should not throw
        var act = async () => await _tokenService.RevokeRefreshTokenAsync("non-existent-token");
        await act.Should().NotThrowAsync();
    }
}
