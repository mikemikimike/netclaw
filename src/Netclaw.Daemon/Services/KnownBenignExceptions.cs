// -----------------------------------------------------------------------
// <copyright file="KnownBenignExceptions.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
namespace Netclaw.Daemon.Services;

internal static class KnownBenignExceptions
{
    private const string McpSessionHandlerSendMarker =
        "ModelContextProtocol.McpSessionHandler.SendMessageAsync";

    /// <summary>
    /// Backstop for #2258. <c>DiscardedSendObservingTransport</c> observes the MCP SDK's
    /// discarded sends at the source. It cannot see one case:
    /// <c>McpSessionHandler.SendMessageAsync</c> can throw at
    /// <c>ThrowIfCancellationRequested()</c> during shutdown or hot reload, before it
    /// calls the transport. This predicate matches a transport-class exception that
    /// passed through that SDK frame. Every inner exception must match, so a real
    /// daemon bug in the same aggregate still produces a crash report.
    /// <para>
    /// Known gaps that still produce a crash report: an <c>McpProtocolException</c> from a
    /// 400 response with a JSON-RPC error body, an <c>McpException</c> from a failed OAuth
    /// token refresh, and the SSE transport's "Transport not connected"
    /// <c>InvalidOperationException</c> after dispose. Those types can also mean a real
    /// fault, so this predicate does not match them.
    /// </para>
    /// Delete when the SDK observes these sends itself.
    /// </summary>
    public static bool IsMcpSessionSendFailure(Exception? exception)
    {
        if (exception is null)
            return false;

        if (exception is AggregateException aggregate)
        {
            var inners = aggregate.Flatten().InnerExceptions;
            if (inners.Count == 0)
                return false;

            foreach (var inner in inners)
            {
                if (!MatchesMcpSessionSendFailure(inner))
                    return false;
            }

            return true;
        }

        return MatchesMcpSessionSendFailure(exception);
    }

    private static bool MatchesMcpSessionSendFailure(Exception exception)
        => exception is HttpRequestException or IOException or OperationCanceledException
            && exception.StackTrace is { } stackTrace
            && stackTrace.Contains(McpSessionHandlerSendMarker, StringComparison.Ordinal);
}
