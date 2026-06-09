using FluentAssertions;
using SecureApiDemo.Models;
using Xunit;

namespace SecureApiDemo.Tests.Models;

public class RefreshTokenTests
{
    // ── IsExpired Tests ───────────────────────────────────────────────────────

    [Fact]
    public void IsExpired_FutureExpiry_ReturnsFalse()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        // Assert
        token.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void IsExpired_PastExpiry_ReturnsTrue()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(-1)
        };

        // Assert
        token.IsExpired.Should().BeTrue();
    }

    // ── IsRevoked Tests ───────────────────────────────────────────────────────

    [Fact]
    public void IsRevoked_NotRevoked_ReturnsFalse()
    {
        // Arrange
        var token = new RefreshToken { RevokedAt = null };

        // Assert
        token.IsRevoked.Should().BeFalse();
    }

    [Fact]
    public void IsRevoked_Revoked_ReturnsTrue()
    {
        // Arrange
        var token = new RefreshToken { RevokedAt = DateTime.UtcNow };

        // Assert
        token.IsRevoked.Should().BeTrue();
    }

    // ── IsActive Tests ────────────────────────────────────────────────────────

    [Fact]
    public void IsActive_NotExpiredNotRevoked_ReturnsTrue()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            RevokedAt = null
        };

        // Assert
        token.IsActive.Should().BeTrue();
    }

    [Fact]
    public void IsActive_Expired_ReturnsFalse()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(-1),
            RevokedAt = null
        };

        // Assert
        token.IsActive.Should().BeFalse();
    }

    [Fact]
    public void IsActive_Revoked_ReturnsFalse()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            RevokedAt = DateTime.UtcNow
        };

        // Assert
        token.IsActive.Should().BeFalse();
    }

    [Fact]
    public void IsActive_ExpiredAndRevoked_ReturnsFalse()
    {
        // Arrange
        var token = new RefreshToken
        {
            ExpiresAt = DateTime.UtcNow.AddDays(-1),
            RevokedAt = DateTime.UtcNow
        };

        // Assert
        token.IsActive.Should().BeFalse();
    }
}
