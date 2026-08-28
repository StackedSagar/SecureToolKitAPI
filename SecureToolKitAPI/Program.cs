using Azure.Identity;
using SecureToolKitAPI.Application;
using SecureToolKitAPI.ExceptionHandling;

var builder = WebApplication.CreateBuilder(args);
// Read from appsettings.json
var environmentNameFromConfig = builder.Configuration["EnvironmentName"];

var keyVaultUri = builder.Configuration["KeyVaultUri"];
if (!string.IsNullOrWhiteSpace(keyVaultUri) && !builder.Environment.IsEnvironment("Testing"))
{
    builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUri), new DefaultAzureCredential());
}

builder.Host.UseDefaultServiceProvider(options =>
{
    options.ValidateScopes = true;  // Reject captive dependencies: a singleton capturing a scoped service.
    options.ValidateOnBuild = true; // Prove at startup that every registration can be constructed.
});

// Cryptography layer: the key generators, encryption methods and signature methods, plus the
// registries that resolve one from the identifier a caller supplies. Registered as singletons.
builder.Services.AddCryptographyMethods();

// Application layer: the per-request orchestration behind the application service interfaces.
builder.Services.AddCryptographyApplicationServices();

// API layer.
builder.Services.AddControllers();
builder.Services.AddProblemDetails();  // Return RFC 9457 problem responses, and translate exceptions without leaking cryptographic details.
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddEndpointsApiExplorer(); // Add Swagger/OpenAPI services
builder.Services.AddHealthChecks(); // Add health checks services
builder.Services.AddSwaggerGen(options =>
{
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath);
});
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.Limits.MaxRequestBodySize = 50 * 1024 * 1024; // 50 MB
});

var app = builder.Build();
app.UseExceptionHandler(); // Configure the HTTP request pipeline.

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapGet("/ConfigEnvironment", () =>
{
    return new
    {
        Environment = app.Environment.EnvironmentName,
        EnvironmentName = environmentNameFromConfig ?? string.Empty,
        ApplicationVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? string.Empty
    };
});

app.MapGet("/KeyVaultTest", (IConfiguration configuration) =>
{
    var value = configuration["LearningSecret"];

    return Results.Ok(new
    {
        Source = "Azure Key Vault",
        Value = value
    });
});

app.MapHealthChecks("/health");
app.MapHealthChecks("/healthcheck");
app.MapControllers();
app.Run();