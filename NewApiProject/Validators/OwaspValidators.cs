using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SecureApiDemo.Validators;

/// <summary>
/// OWASP A03:2021 — Injection + A04:2021 — Insecure Design
///
/// Custom validators enforce strict input validation on all DTOs.
/// This prevents injection attacks and enforces business rules at the model level.
/// </summary>

/// <summary>
/// Validates that a string does not contain SQL injection patterns.
/// </summary>
public class NoSqlInjectionAttribute : ValidationAttribute
{
    private static readonly Regex _pattern = new(
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b)|(--|;|')",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    protected override ValidationResult? IsValid(object? value, ValidationContext context)
    {
        if (value is string str && _pattern.IsMatch(str))
            return new ValidationResult("Input contains invalid characters.");

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that a string does not contain XSS patterns.
/// </summary>
public class NoXssAttribute : ValidationAttribute
{
    private static readonly Regex _pattern = new(
        @"(<script|</script|javascript:|onerror=|onload=|eval\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    protected override ValidationResult? IsValid(object? value, ValidationContext context)
    {
        if (value is string str && _pattern.IsMatch(str))
            return new ValidationResult("Input contains invalid characters.");

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates that a username only contains safe characters.
/// </summary>
public class SafeUsernameAttribute : ValidationAttribute
{
    private static readonly Regex _pattern = new(
        @"^[a-zA-Z0-9._-]+$",
        RegexOptions.Compiled);

    protected override ValidationResult? IsValid(object? value, ValidationContext context)
    {
        if (value is string str && !_pattern.IsMatch(str))
            return new ValidationResult(
                "Username can only contain letters, numbers, dots, hyphens and underscores.");

        return ValidationResult.Success;
    }
}

/// <summary>
/// Validates password strength per OWASP guidelines.
/// </summary>
public class StrongPasswordAttribute : ValidationAttribute
{
    protected override ValidationResult? IsValid(object? value, ValidationContext context)
    {
        if (value is not string password)
            return new ValidationResult("Password is required.");

        var errors = new List<string>();

        if (password.Length < 8)
            errors.Add("at least 8 characters");
        if (!password.Any(char.IsUpper))
            errors.Add("one uppercase letter");
        if (!password.Any(char.IsLower))
            errors.Add("one lowercase letter");
        if (!password.Any(char.IsDigit))
            errors.Add("one number");

        if (errors.Any())
            return new ValidationResult(
                $"Password must contain: {string.Join(", ", errors)}.");

        return ValidationResult.Success;
    }
}
