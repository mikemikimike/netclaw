// -----------------------------------------------------------------------
// <copyright file="OAuthRefreshFailureLogHandler.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Netclaw.Security;

namespace Netclaw.Daemon.Mcp;

/// <summary>
/// Logs a token endpoint rejection of an OAuth refresh grant.
/// </summary>
/// <remarks>
/// The MCP SDK returns a null access token when the token endpoint rejects a refresh grant
/// and discards the response. It then falls through to interactive authorization, which a
/// background connection cannot complete. Without this line the log cannot tell a rejected
/// grant from a grant that the SDK never sent. The handler logs only the endpoint, the HTTP
/// status, and the two RFC 6749 error fields. It never logs the request body, because that
/// body carries the refresh token and the client secret.
/// </remarks>
internal sealed class OAuthRefreshFailureLogHandler(ILogger logger) : DelegatingHandler
{
    private const string FormContentType = "application/x-www-form-urlencoded";
    private const string RefreshTokenGrant = "grant_type=refresh_token";
    private const int MaxDescriptionLength = 200;

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
        var response = await base.SendAsync(request, cancellationToken);
        if (response.IsSuccessStatusCode
            || !requestBody.Contains(RefreshTokenGrant, StringComparison.Ordinal))
            return response;

        // Buffer the small error body so the SDK can still read the response after this.
        await response.Content.LoadIntoBufferAsync(cancellationToken);
        var (error, description) = ReadOAuthError(await response.Content.ReadAsStringAsync(cancellationToken));
        logger.LogWarning(
            "OAuth token endpoint {TokenEndpoint} rejected a refresh grant: HTTP {Status} error={Error} " +
            "error_description={Description}. The MCP SDK discards this response and requests interactive " +
            "authorization, so the stored refresh token is no longer usable.",
            request.RequestUri?.GetLeftPart(UriPartial.Path) ?? "<unknown>",
            (int)response.StatusCode,
            error ?? "<none>",
            description ?? "<none>");
        return response;
    }

    private static (string? Error, string? Description) ReadOAuthError(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return (null, null);

        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return (null, null);
            return (Read(document.RootElement, "error"), Read(document.RootElement, "error_description"));
        }
        catch (JsonException)
        {
            // A non-JSON body has no standard field to report. The raw body stays unlogged.
            return (null, null);
        }

        static string? Read(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
                return null;
            var value = SecretOutputRedactor.Redact(property.GetString() ?? string.Empty);
            return value.Length > MaxDescriptionLength ? value[..MaxDescriptionLength] : value;
        }
    }
}
