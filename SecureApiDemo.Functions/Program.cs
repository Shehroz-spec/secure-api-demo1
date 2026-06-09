using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Data;
using SecureApiDemo.Functions.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        // SQL Server
        services.AddDbContext<FunctionsDbContext>(options =>
            options.UseSqlServer(
                context.Configuration["SqlConnectionString"]
                ?? throw new InvalidOperationException("SqlConnectionString not configured.")));

        // Services
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<IAlertService, AlertService>();

        // Logging
        services.AddLogging(logging =>
        {
            logging.AddConsole();
        });
    })
    .Build();

host.Run();