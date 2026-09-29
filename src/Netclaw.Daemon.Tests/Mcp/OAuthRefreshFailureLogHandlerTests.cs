// -----------------------------------------------------------------------
// <copyright file="OAuthRefreshFailureLogHandlerTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using Netclaw.Daemon.Mcp;
using Xunit;

namespace Netclaw.Daemon.Tests.Mcp;

public sealed class OAuthRefreshFailureLogHandlerTests
{
    [Fact]
    public async Task LogsOnlyRejectedRefreshGrantsAndNeverTheRequestCredentials()
    {
        var ct = TestContext.Current.CancellationToken;
        var logger = new RecordingLogger<OAuthRefreshFailureLogHandlerTests>();
        using var client = new HttpClient(new OAuthRefreshFailureLogHandler(logger)
        {
            InnerHandler = new StubHandler(
                HttpStatusCode.BadRequest,
                """{"error":"invalid_grant","error_description":"refresh token reused"}"""),
        });

        using var codeExchange = await client.SendAsync(TokenRequest("grant_type=authorization_code&code=abc"), ct);
        Assert.Empty(logger.Entries);

        using var refresh = await client.SendAsync(
            TokenRequest("grant_type=refresh_token&refresh_token=rt-secret-value&client_secret=cs-secret-value"),
            ct);

        var entry = Assert.Single(logger.Entries);
        Assert.Contains("https://auth.example/token", entry, StringComparison.Ordinal);
        Assert.Contains("HTTP 400 error=invalid_grant error_description=refresh token reused", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret-value", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("cs-secret-value", entry, StringComparison.Ordinal);

        // The SDK still reads the rejected response after the handler inspected it.
        Assert.Contains("invalid_grant", await refresh.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
    }

    private static HttpRequestMessage TokenRequest(string body) => new(HttpMethod.Post, "https://auth.example/token?x=1")
    {
        Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"),
    };

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
    }
}
