// ──────────────────────────────────────────────────────────────────────────────
// WelcomeEmailFunction — Service Bus Trigger
//
// This function requires Azure Service Bus resource + package:
//   Microsoft.Azure.WebJobs.Extensions.ServiceBus
//
// To enable:
//   1. Create Azure Service Bus namespace in Azure Portal
//   2. dotnet add package Microsoft.Azure.WebJobs.Extensions.ServiceBus
//   3. Add connection string to local.settings.json
//   4. Uncomment the code below
//
// Interview talking point:
// "When a user registers, the API publishes a message to Azure Service Bus.
//  This Function picks it up asynchronously and sends a welcome email —
//  completely decoupled from the API response, keeping register fast."
// ──────────────────────────────────────────────────────────────────────────────

/*
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Models;
using SecureApiDemo.Functions.Services;
using System.Text.Json;

namespace SecureApiDemo.Functions.Functions;

public class WelcomeEmailFunction
{
    private readonly IEmailService _emailService;
    private readonly ILogger<WelcomeEmailFunction> _logger;

    public WelcomeEmailFunction(IEmailService emailService, ILogger<WelcomeEmailFunction> logger)
    {
        _emailService = emailService;
        _logger       = logger;
    }

    [Function("SendWelcomeEmail")]
    public async Task Run(
        [ServiceBusTrigger("%ServiceBusQueueName%", Connection = "ServiceBusConnectionString")]
        string messageBody,
        FunctionContext context)
    {
        var payload = JsonSerializer.Deserialize<WelcomeEmailMessage>(messageBody);
        if (payload is null) return;

        await _emailService.SendWelcomeEmailAsync(
            email:    payload.Email,
            username: payload.Username,
            role:     payload.Role);

        _logger.LogInformation("Welcome email sent to {Email}", payload.Email);
    }
}
*/