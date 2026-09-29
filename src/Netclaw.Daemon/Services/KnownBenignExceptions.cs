// -----------------------------------------------------------------------
// <copyright file="KnownBenignExceptions.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
namespace Netclaw.Daemon.Services;

/// <summary>
/// A predicate that marks an unobserved task exception as known and benign.
/// <see cref="DaemonCrashMonitor"/> logs a match as a warning with
/// <paramref name="Description"/> and does not write a crash report.
/// </summary>
internal sealed record BenignUnobservedExceptionFilter(string Description, Func<Exception, bool> Matches);

internal static class KnownBenignExceptions
{
    private const string McpSessionHandlerSendMarker =
        "ModelContextProtocol.McpSessionHandler.SendMessageAsync";

    // Client session transports whose SendMessageAsync does network or pipe I/O.
    // StdioClientSessionTransport wraps StreamClientSessionTransport and can rethrow
    // its own IOException when the server process exits, so both frames are listed.
    private static readonly string[] McpClientTransportSendMarkers =
    [
        "ModelContextProtocol.Client.StreamableHttpClientSessionTransport.SendMessageAsync",
        "ModelContextProtocol.Client.SseClientSessionTransport.SendMessageAsync",
        "ModelContextProtocol.Client.StreamClientSessionTransport.SendMessageAsync",
        "ModelContextProtocol.Client.StdioClientSessionTransport.SendMessageAsync",
    ];

    public static readonly BenignUnobservedExceptionFilter McpClientTransportSendFailure = new(
        "MCP client transport send failed inside a ModelContextProtocol SDK background task "
        + "(MCP server unreachable or returned an HTTP error). The daemon continues to run.",
        IsMcpClientTransportSendFailure);

    /// <summary>
    /// ModelContextProtocol SDK 2.2.0 discards the send task in two places:
    /// the per-message fire-and-forget in <c>McpSessionHandler.ProcessMessagesCoreAsync</c>
    /// (it sends a JSON-RPC error reply from inside its catch block), and the
    /// <c>notifications/cancelled</c> send in <c>RegisterCancellation</c>.
    /// When the MCP server returns an HTTP error (for example 502) or the
    /// connection drops, the send throws and nothing observes the task (#2258).
    /// Netclaw has no handle on these tasks, so the crash monitor must classify them.
    /// Every inner exception must match, so a real daemon bug in the same aggregate
    /// still produces a crash report.
    /// Delete when the SDK observes these send failures itself.
    /// </summary>
    public static bool IsMcpClientTransportSendFailure(Exception? exception)
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
                if (!MatchesMcpTransportSendFailure(inner))
                    return false;
            }

            return true;
        }

        return MatchesMcpTransportSendFailure(exception);
    }

    private static bool MatchesMcpTransportSendFailure(Exception exception)
    {
        if (exception is not (HttpRequestException or IOException or OperationCanceledException))
            return false;

        var stackTrace = exception.StackTrace;
        if (stackTrace is null
            || !stackTrace.Contains(McpSessionHandlerSendMarker, StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var marker in McpClientTransportSendMarkers)
        {
            if (stackTrace.Contains(marker, StringComparison.Ordinal))
                return true;
        }

        return false;
    }
}
