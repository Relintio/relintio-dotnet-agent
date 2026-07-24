# Relintio WAF Protection Agent SDK (.NET)

Official ASP.NET Core middleware WAF integration for Relintio.

## Installation

Install the package via NuGet:

```bash
dotnet add package Relintio.Agent
```

## Dashboard Deployment Workflow

1. Open **Dashboard → Deployment**, select **.NET**, and download the prepared ASP.NET Core starter.
2. Register the Relintio middleware before mapping protected endpoints.
3. Restart the service, then open one public HTTP endpoint.
4. Enter that exact URL or public IP endpoint in Relintio and select **Verify target**.

The SDK reports runtime kind `dotnet` and its version during rule synchronization. Policy revisions are received automatically.

Or via the Package Manager Console:

```powershell
Install-Package Relintio.Agent
```

## Features

- **Rules Sync Engine:** Runs on a non-blocking thread-safe background thread to synchronize rules from the console.
- **Fast Local Match:** In-memory request assessment against rules Cache.
- **ASP.NET Core Middleware:** Standard middleware pattern compatible with minimal APIs and MVC controllers.
- **Telemetry Loop:** Non-blocking telemetry delivery back to the Relintio API.

## Quickstart

Add the agent services and register the middleware in your `Program.cs`:

```csharp
using Relintio;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// 1. Initialize and start the Relintio Agent
var agent = new Agent(new AgentConfig
{
    LicenseKey = "YOUR_LICENSE_KEY",
    Domain = "example.com",
    ApiUrl = "https://api.relintio.com/v1",
    SyncIntervalSeconds = 10
});
agent.StartSync();

// 2. Register the Relintio WAF Middleware
app.UseRelintio(agent);

app.MapGet("/", () => new { message = "Protected .NET Application is running" });

app.Run();
```
