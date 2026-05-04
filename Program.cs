using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// --- HTTP Client: Auth Service ---
builder.Services.AddHttpClient<AuthServiceClient>(client =>
{
    var baseUrl = Environment.GetEnvironmentVariable("AUTH_SVC_URL") ?? "http://ppops-auth-svc:8080";
    client.BaseAddress = new Uri(baseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromSeconds(10);
});

var app = builder.Build();

app.MapControllers();
app.Run();

// --- HTTP Client Classes ---
public class AuthServiceClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<AuthServiceClient> _logger;

    public AuthServiceClient(HttpClient httpClient, ILogger<AuthServiceClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/validate");
            request.Headers.Add("Authorization", $"Bearer {token}");
            var response = await _httpClient.SendAsync(request);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate token with auth-svc");
            return false;
        }
    }
}

// --- Models ---
public record AuditLogEntry(string EventType, string UserId, string Resource, string Action, DateTime Timestamp, Dictionary<string, string>? Metadata = null);
public record AuditLogRequest(string EventType, string UserId, string Resource, string Action, Dictionary<string, string>? Metadata = null);

// --- Controller ---
[ApiController]
[Route("api/audit")]
public class AuditController : ControllerBase
{
    private static readonly List<AuditLogEntry> _auditLog = new();
    private readonly AuthServiceClient _authClient;
    private readonly ILogger<AuditController> _logger;

    public AuditController(AuthServiceClient authClient, ILogger<AuditController> logger)
    {
        _authClient = authClient;
        _logger = logger;
    }

    [HttpPost("log")]
    public async Task<IActionResult> LogEvent([FromBody] AuditLogRequest request)
    {
        var token = HttpContext.Request.Headers["Authorization"].FirstOrDefault()?.Replace("Bearer ", "");
        if (!string.IsNullOrEmpty(token))
        {
            var isValid = await _authClient.ValidateTokenAsync(token);
            if (!isValid)
                return Unauthorized(new { error = "Invalid authentication token" });
        }

        var entry = new AuditLogEntry(
            request.EventType,
            request.UserId,
            request.Resource,
            request.Action,
            DateTime.UtcNow,
            request.Metadata
        );

        _auditLog.Add(entry);
        _logger.LogInformation("Audit event logged: {EventType} by {UserId} on {Resource}", entry.EventType, entry.UserId, entry.Resource);

        return Ok(new { status = "logged", timestamp = entry.Timestamp });
    }

    [HttpGet("events")]
    public IActionResult GetEvents([FromQuery] string? userId = null, [FromQuery] string? eventType = null, [FromQuery] int limit = 50)
    {
        var query = _auditLog.AsEnumerable();

        if (!string.IsNullOrEmpty(userId))
            query = query.Where(e => e.UserId == userId);
        if (!string.IsNullOrEmpty(eventType))
            query = query.Where(e => e.EventType == eventType);

        var results = query.OrderByDescending(e => e.Timestamp).Take(limit).ToList();
        return Ok(new { count = results.Count, events = results });
    }
}