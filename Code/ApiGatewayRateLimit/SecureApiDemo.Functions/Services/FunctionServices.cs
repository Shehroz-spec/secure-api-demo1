using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Models;

namespace SecureApiDemo.Functions.Services;

public interface IEmailService
{
    Task SendWelcomeEmailAsync(string email, string username, string role);
}

public interface IAlertService
{
    Task SendSuspiciousLoginAlertAsync(SuspiciousLoginAlert alert);
}

/// <summary>
/// Email service — simulated in dev.
/// In production replace with SendGrid or Azure Communication Services:
///   var client = new SendGridClient(apiKey);
///   var msg = MailHelper.CreateSingleEmail(from, to, subject, text, html);
///   await client.SendEmailAsync(msg);
/// </summary>
public class EmailService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IConfiguration config, ILogger<EmailService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public async Task SendWelcomeEmailAsync(string email, string username, string role)
    {
        // ── Simulated email send ──────────────────────────────────────────────
        // In production replace with:
        // var sendGridClient = new SendGridClient(_config["SendGrid:ApiKey"]);
        // var msg = MailHelper.CreateSingleEmail(
        //     from:    new EmailAddress("noreply@secureapidemo.com", "SecureApiDemo"),
        //     to:      new EmailAddress(email, username),
        //     subject: "Welcome to SecureApiDemo!",
        //     plainTextContent: $"Hi {username}, your account has been created with role: {role}.",
        //     htmlContent: $"<h1>Welcome {username}!</h1><p>Role: {role}</p>");
        // await sendGridClient.SendEmailAsync(msg);

        await Task.Delay(100); // Simulate async email send

        _logger.LogInformation(
            "Welcome email sent to {Email} for user {Username} (Role: {Role})",
            email, username, role);
    }
}

/// <summary>
/// Alert service — sends admin notifications for security events.
/// In production replace with SendGrid, Teams webhook, or PagerDuty.
/// </summary>
public class AlertService : IAlertService
{
    private readonly IConfiguration _config;
    private readonly ILogger<AlertService> _logger;

    public AlertService(IConfiguration config, ILogger<AlertService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public async Task SendSuspiciousLoginAlertAsync(SuspiciousLoginAlert alert)
    {
        var adminEmail = _config["AdminEmail"] ?? "admin@secureapidemo.com";

        // ── Simulated alert ───────────────────────────────────────────────────
        // In production replace with:
        // var sendGridClient = new SendGridClient(_config["SendGrid:ApiKey"]);
        // var msg = MailHelper.CreateSingleEmail(
        //     from:    new EmailAddress("security@secureapidemo.com"),
        //     to:      new EmailAddress(adminEmail, "Admin"),
        //     subject: $"⚠️ Suspicious Login: {alert.Username}",
        //     plainTextContent: $"IP: {alert.IpAddress} | Attempts: {alert.FailedAttempts}",
        //     htmlContent: BuildAlertHtml(alert));
        // await sendGridClient.SendEmailAsync(msg);

        await Task.Delay(100); // Simulate async alert send

        _logger.LogWarning(
            "SECURITY ALERT sent to {AdminEmail}: User={Username} IP={IP} Attempts={Attempts}",
            adminEmail, alert.Username, alert.IpAddress, alert.FailedAttempts);
    }
}
