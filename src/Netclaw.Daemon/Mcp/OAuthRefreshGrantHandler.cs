// -----------------------------------------------------------------------
// <copyright file="OAuthRefreshGrantHandler.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Netclaw.Security;

namespace Netclaw.Daemon.Mcp;

/// <summary>
/// Coordinates and reports the OAuth refresh grants that the MCP SDK sends for one
/// connection.
/// </summary>
/// <remarks>
/// <para>
/// The SDK serializes refreshes per connection only. During a reconnect two connections of
/// one server can read the same refresh token and both redeem it. A rotating provider accepts
/// the first grant and rejects the second with <c>invalid_grant</c>, and the SDK then asks for
/// interactive authorization although the store holds a live refresh token. This handler sits
/// on the SDK's token request path, so it closes that race:
/// </para>
/// <list type="bullet">
/// <item>It holds the server's refresh gate from the grant until the store records the
/// result.</item>
/// <item>It sends the refresh token the store holds now, when the connection follows the
/// active record and holds an older one.</item>
/// </list>
/// <para>
/// The SDK also discards a rejected grant's response. This handler logs the endpoint, the
/// status, and the two RFC 6749 error fields. It never logs a request body, because that body
/// carries the refresh token and the client secret.
/// </para>
/// </remarks>
internal sealed class OAuthRefreshGrantHandler(ILogger logger, McpOAuthTokenCache? cache) : DelegatingHandler
{
    private const string FormContentType = "application/x-www-form-urlencoded";
    private const string RefreshTokenGrant = "grant_type=refresh_token";
    private const string RefreshTokenField = "refresh_token";
    private const int MaxFieldLength = 200;

    /// <summary>A token response is small. A larger body is not parsed.</summary>
    private const int MaxBufferedBody = 64 * 1024;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.Method != HttpMethod.Post
            || request.Content?.Headers.ContentType?.MediaType != FormContentType)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        var requestBody = await request.Content.ReadAsStringAsync(cancellationToken);
        if (!requestBody.Contains(RefreshTokenGrant, StringComparison.Ordinal))
            return await base.SendAsync(request, cancellationToken);

        if (cache is null)
        {
            var uncoordinated = await base.SendAsync(request, cancellationToken);
            await LogIfRejectedAsync(request, uncoordinated, cancellationToken);
            return uncoordinated;
        }

        var gate = cache.RefreshGate;
        await gate.WaitAsync(cancellationToken);
        try
        {
            var form = ParseForm(requestBody);
            var presented = form.FirstOrDefault(pair => pair.Key == RefreshTokenField).Value;
            var current = cache.GetRedeemableRefreshToken();
            if (current is not null && !string.Equals(current, presented, StringComparison.Ordinal))
            {
                request.Content = new FormUrlEncodedContent(form
                    .Select(pair => pair.Key == RefreshTokenField
                        ? new KeyValuePair<string, string>(pair.Key, current)
                        : pair)
                    .ToList());
                presented = current;
                logger.LogInformation(
                    "MCP server '{Name}' redeemed the refresh token that another connection rotated",
                    cache.ServerName.Value);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                await LogIfRejectedAsync(request, response, cancellationToken);
                return response;
            }

            if (presented is not null
                && await ReadBoundedAsync(response, cancellationToken) is { } body
                && ReadIssuedTokens(body) is { } issued)
                cache.RecordRefreshGrant(presented, issued);
            return response;
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task LogIfRejectedAsync(
        HttpRequestMessage request,
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
            return;

        var (error, description) = ReadOAuthError(await ReadBoundedAsync(response, cancellationToken));
        logger.LogWarning(
            "OAuth token endpoint {TokenEndpoint} rejected a refresh grant{Server}: HTTP {Status} error={Error} " +
            "error_description={Description}. {Meaning} The MCP SDK discards this response and requests " +
            "interactive authorization.",
            request.RequestUri?.GetLeftPart(UriPartial.Path) ?? "<unknown>",
            cache is null ? string.Empty : $" for MCP server '{cache.ServerName.Value}'",
            (int)response.StatusCode,
            error ?? "<none>",
            description ?? "<none>",
            DescribeRejection(response.StatusCode, error));
    }

    private static string DescribeRejection(HttpStatusCode status, string? error)
        => error switch
        {
            "invalid_grant" => "The authorization server no longer accepts this refresh token: it expired, was revoked, or was already used.",
            "invalid_client" or "unauthorized_client" => "The authorization server rejected the client credentials.",
            _ when status is HttpStatusCode.TooManyRequests || (int)status >= 500
                => "The authorization server failed or throttled the request; the refresh token can still be valid.",
            _ => "The authorization server rejected the refresh grant.",
        };

    /// <summary>
    /// Buffers a response body of at most <see cref="MaxBufferedBody"/> bytes so the SDK can
    /// still read it. Returns <c>null</c> for a larger or unreadable body.
    /// </summary>
    private static async Task<string?> ReadBoundedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxBufferedBody)
            return null;

        try
        {
            await response.Content.LoadIntoBufferAsync(MaxBufferedBody, cancellationToken);
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch (HttpRequestException)
        {
            // Diagnostics and grant records are best effort; the SDK reports the transport fault.
            return null;
        }
    }

    private static List<KeyValuePair<string, string>> ParseForm(string body)
        => body.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(segment =>
            {
                var parts = segment.Split('=', 2);
                return new KeyValuePair<string, string>(
                    WebUtility.UrlDecode(parts[0]),
                    parts.Length == 2 ? WebUtility.UrlDecode(parts[1]) : string.Empty);
            })
            .ToList();

    private static McpOAuthIssuedTokens? ReadIssuedTokens(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || ReadString(root, "access_token") is not { Length: > 0 } accessToken)
                return null;

            int? expiresIn = root.TryGetProperty("expires_in", out var expires) && expires.TryGetInt32(out var seconds)
                ? seconds
                : null;
            return new McpOAuthIssuedTokens(
                accessToken,
                ReadString(root, "refresh_token"),
                expiresIn,
                ReadString(root, "token_type") ?? "Bearer",
                ReadString(root, "scope"));
        }
        catch (JsonException)
        {
            // The SDK parses the same body and reports a malformed token response itself.
            return null;
        }
    }

    private static (string? Error, string? Description) ReadOAuthError(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return (null, null);

        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return (null, null);
            return (Redacted(ReadString(document.RootElement, "error")),
                Redacted(ReadString(document.RootElement, "error_description")));
        }
        catch (JsonException)
        {
            // A non-JSON body has no standard field to report. The raw body stays unlogged.
            return (null, null);
        }

        static string? Redacted(string? value)
        {
            if (value is null)
                return null;
            var redacted = SecretOutputRedactor.Redact(value);
            return redacted.Length > MaxFieldLength ? redacted[..MaxFieldLength] : redacted;
        }
    }

    private static string? ReadString(JsonElement root, string name)
        => root.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}
