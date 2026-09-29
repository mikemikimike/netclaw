// -----------------------------------------------------------------------
// <copyright file="OAuthRefreshGrantHandlerTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using ModelContextProtocol.Authentication;
using Netclaw.Configuration;
using Netclaw.Configuration.Secrets;
using Netclaw.Daemon.Mcp;
using Netclaw.Tests.Utilities;
using Netclaw.Tools;
using Xunit;

namespace Netclaw.Daemon.Tests.Mcp;

public sealed class OAuthRefreshGrantHandlerTests : IDisposable
{
    private const string Resource = "https://mcp.example.com/tools";
    private const string TokenEndpoint = "https://auth.example/token";
    private static readonly McpServerName ServerName = new("race-server");
    private static readonly McpOAuthClientIdentity Client = new("client", null, dynamicClientRegistration: false);
    private readonly DisposableTempDir _dir = new();

    [Fact]
    public async Task LogsOnlyRejectedRefreshGrantsAndNeverTheRequestCredentials()
    {
        var ct = TestContext.Current.CancellationToken;
        var logger = new RecordingLogger<OAuthRefreshGrantHandlerTests>();
        var runtime = new McpClientRuntime(logger, new StubHandler(
            HttpStatusCode.BadRequest,
            """{"error":"invalid_grant","error_description":"refresh token reused"}"""));
        using var client = runtime.CreateHttpClient(tokenCache: null);

        using var codeExchange = await client.SendAsync(TokenRequest("grant_type=authorization_code&code=abc"), ct);
        Assert.Empty(logger.Entries);

        using var refresh = await client.SendAsync(
            TokenRequest("grant_type=refresh_token&refresh_token=rt-secret-value&client_secret=cs-secret-value"),
            ct);

        var entry = Assert.Single(logger.Entries);
        Assert.Contains(TokenEndpoint, entry, StringComparison.Ordinal);
        Assert.Contains("HTTP 400 error=invalid_grant error_description=refresh token reused", entry, StringComparison.Ordinal);
        Assert.Contains("no longer accepts this refresh token", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret-value", entry, StringComparison.Ordinal);
        Assert.DoesNotContain("cs-secret-value", entry, StringComparison.Ordinal);

        // The SDK still reads the rejected response after the handler inspected it.
        Assert.Contains("invalid_grant", await refresh.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentConnectionsRedeemEachRotatedRefreshTokenOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new McpOAuthCredentialStore(
            new NetclawPaths(_dir.Path),
            TimeProvider.System,
            new NullSecretsProtector(),
            NullLogger<McpOAuthCredentialStore>.Instance);
        var live = store.CreateTokenCache(ServerName, Resource, Client, false);
        await live.StoreTokensAsync(Tokens("access-1", "refresh-1"), ct);
        store.Publish(live, CancellationToken.None);
        var candidate = store.CreateTokenCache(ServerName, Resource, Client, false);

        var endpoint = new RotatingTokenEndpoint();
        var runtime = new McpClientRuntime(NullLogger.Instance, endpoint);
        using var liveClient = runtime.CreateHttpClient(live);
        using var candidateClient = runtime.CreateHttpClient(candidate);

        // Both SDK providers read refresh-1 before either stores a result.
        var liveRefresh = liveClient.SendAsync(RefreshRequest("refresh-1"), ct);
        await endpoint.FirstRequestReceived.Task.WaitAsync(ct);
        Assert.Equal(0, live.RefreshGate.CurrentCount);
        var candidateRefresh = candidateClient.SendAsync(RefreshRequest("refresh-1"), ct);
        endpoint.ReleaseFirstRequest.TrySetResult(true);

        using var liveResponse = await liveRefresh;
        using var candidateResponse = await candidateRefresh;

        Assert.True(liveResponse.IsSuccessStatusCode);
        Assert.True(candidateResponse.IsSuccessStatusCode);
        Assert.Equal(["refresh-1", "refresh-2"], endpoint.Presented);
        Assert.Equal("refresh-3", store.GetActiveForTests(ServerName)?.RefreshToken?.Value);

        // The live SDK provider stores its own, older grant after the candidate's grant.
        await live.StoreTokensAsync(Tokens("access-2", "refresh-2"), ct);
        Assert.Equal("access-3", store.GetActiveForTests(ServerName)?.AccessToken.Value);
        Assert.Equal("refresh-3", store.GetActiveForTests(ServerName)?.RefreshToken?.Value);
    }

    private static TokenContainer Tokens(string accessToken, string refreshToken) => new()
    {
        AccessToken = accessToken,
        RefreshToken = refreshToken,
        TokenType = "Bearer",
        ExpiresIn = 3600,
        ObtainedAt = DateTimeOffset.UtcNow,
    };

    private static HttpRequestMessage RefreshRequest(string refreshToken)
        => TokenRequest($"grant_type=refresh_token&refresh_token={refreshToken}&client_id=client");

    private static HttpRequestMessage TokenRequest(string body) => new(HttpMethod.Post, TokenEndpoint + "?x=1")
    {
        Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded"),
    };

    public void Dispose() => _dir.Dispose();

    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>
    /// A strict rotating token endpoint: each refresh token is accepted once and replaced.
    /// The first request waits until the test releases it.
    /// </summary>
    private sealed class RotatingTokenEndpoint : HttpMessageHandler
    {
        private readonly ConcurrentQueue<string> _presented = new();
        private readonly ConcurrentDictionary<string, byte> _live = new(StringComparer.Ordinal) { ["refresh-1"] = 0 };
        private int _sequence = 1;

        public TaskCompletionSource<bool> FirstRequestReceived { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<bool> ReleaseFirstRequest { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IReadOnlyList<string> Presented => _presented.ToArray();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            var presented = body.Split('&')
                .Select(pair => pair.Split('=', 2))
                .Single(pair => pair[0] == "refresh_token")[1];
            _presented.Enqueue(presented);
            var accepted = _live.TryRemove(presented, out _);
            var sequence = accepted ? Interlocked.Increment(ref _sequence) : 0;
            if (FirstRequestReceived.TrySetResult(true))
                await ReleaseFirstRequest.Task.WaitAsync(cancellationToken);

            if (!accepted)
            {
                return new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent("""{"error":"invalid_grant"}""", Encoding.UTF8, "application/json"),
                };
            }

            _live[$"refresh-{sequence}"] = 0;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    $$"""{"access_token":"access-{{sequence}}","refresh_token":"refresh-{{sequence}}","token_type":"Bearer","expires_in":3600}""",
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }
}
