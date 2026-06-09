# SecureApiDemo.Functions — Azure Functions

Serverless background processing for SecureApiDemo.
Four functions covering the most common enterprise patterns.

## Architecture

```
SecureApiDemo (API)
      │
      ├── User registers ──────────────► Service Bus Queue
      │                                        │
      │                                        ▼
      │                                 WelcomeEmailFunction
      │                                 (sends welcome email)
      │
      ├── Failed login detected ────────► HTTP Trigger
      │                                        │
      │                                        ▼
      │                                 SuspiciousLoginAlertFunction
      │                                 (logs + alerts admin)
      │
      └── Every hour (Timer) ──────────► CleanupExpiredTokensFunction
                                         (deletes expired refresh tokens)

Every night (Timer) ─────────────────► AuditLogArchiverFunction
                                        (archives old logs to Blob Storage)
```

## Functions

| Function | Trigger | Schedule | Purpose |
|---|---|---|---|
| `CleanupExpiredTokens` | Timer | Every hour | Deletes expired/revoked refresh tokens |
| `SendWelcomeEmail` | Service Bus | On message | Sends welcome email on registration |
| `SuspiciousLoginAlert` | HTTP POST | On demand | Logs + alerts admin on brute force |
| `AuditLogArchiver` | Timer | Midnight daily | Archives old logs to Blob Storage |

## Quick Start

### Prerequisites
```bash
# Install Azure Functions Core Tools
npm install -g azure-functions-core-tools@4

# Install Azurite (local storage emulator)
npm install -g azurite
```

### Run Locally
```bash
# Start Azurite in a separate terminal
azurite

# Start Functions
cd SecureApiDemo.Functions
func start
```

### Test Functions Locally

**Test CleanupExpiredTokens (force run):**
```bash
curl -X POST http://localhost:7071/admin/functions/CleanupExpiredTokens \
  -H "Content-Type: application/json" \
  -d "{}"
```

**Test SuspiciousLoginAlert:**
```bash
curl -X POST http://localhost:7071/api/SuspiciousLoginAlert \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "ipAddress": "192.168.1.100",
    "failedAttempts": 6,
    "detectedAt": "2026-01-01T00:00:00Z"
  }'
```

## How to Publish to Azure

```bash
# Login
az login

# Publish
func azure functionapp publish secure-api-functions
```

## How the API Publishes to Service Bus (on Register)

Add this to `AuthController.Register()` in NewApiProject:

```csharp
// After successful user creation — publish to Service Bus
var message = new WelcomeEmailMessage
{
    UserId   = user.Id,
    Username = user.UserName!,
    Email    = user.Email!,
    Role     = role
};

var client  = new ServiceBusClient(connectionString);
var sender  = client.CreateSender("welcome-email-queue");
await sender.SendMessageAsync(
    new ServiceBusMessage(JsonSerializer.Serialize(message)));
```

## How the API Calls the Alert Function

Add this to `SecurityLoggingMiddleware` when 5+ failures detected:

```csharp
// Call the Azure Function HTTP trigger
using var httpClient = new HttpClient();
await httpClient.PostAsJsonAsync(
    "https://secure-api-functions.azurewebsites.net/api/SuspiciousLoginAlert",
    new {
        username       = username,
        ipAddress      = clientIp,
        failedAttempts = 5,
        detectedAt     = DateTime.UtcNow
    });
```

## Environment Variables

| Variable | Description |
|---|---|
| `SqlConnectionString` | SQL Server connection string |
| `ServiceBusConnectionString` | Azure Service Bus connection |
| `ServiceBusQueueName` | Queue name for welcome emails |
| `AdminEmail` | Email to receive security alerts |
| `KeyVaultUri` | Azure Key Vault URI |

## Author

Shehroz Reaz — Software Engineer specializing in secure cloud-native systems.
