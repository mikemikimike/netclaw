// -----------------------------------------------------------------------
// <copyright file="KnownBenignExceptionsTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Netclaw.Daemon.Services;
using Xunit;

namespace Netclaw.Daemon.Tests.Services;

public sealed class KnownBenignExceptionsTests
{
    // Frames from the #2258 crash log: a 502 from an HTTP MCP server, thrown from the
    // SDK's fire-and-forget ProcessMessageAsync.
    private const string StreamableHttpSendStack =
        "   at ModelContextProtocol.HttpResponseMessageExtensions.EnsureSuccessStatusCodeWithResponseBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.Client.StreamableHttpClientSessionTransport.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.McpSessionHandler.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.McpSessionHandler.<>c__DisplayClass36_1.<<ProcessMessagesCoreAsync>g__ProcessMessageAsync|1>d.MoveNext()";

    // Discarded notifications/cancelled send from McpSessionHandler.RegisterCancellation.
    private const string SseCancelledNotificationStack =
        "   at System.Net.Http.HttpConnection.SendAsync(HttpRequestMessage request, Boolean async, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.Client.SseClientSessionTransport.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.McpSessionHandler.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)";

    private const string StdioSendStack =
        "   at ModelContextProtocol.Client.StdioClientSessionTransport.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)\n"
        + "   at ModelContextProtocol.McpSessionHandler.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)";

    // A transport frame without the session handler frame: Netclaw called the
    // transport itself, so Netclaw owns the task and a leak is a Netclaw bug.
    private const string TransportOnlyStack =
        "   at ModelContextProtocol.Client.StreamableHttpClientSessionTransport.SendMessageAsync(JsonRpcMessage message, CancellationToken cancellationToken)\n"
        + "   at Netclaw.Daemon.Mcp.McpClientManager.SomethingAsync()";

    [Fact]
    public void IsMcpClientTransportSendFailure_NonMcpHttpRequestExceptionWithRealStack_IsNotBenign()
    {
        var exception = CaptureThrown(() =>
            throw new HttpRequestException("Response status code does not indicate success: 502 (Bad Gateway)."));

        Assert.NotNull(exception.StackTrace);
        Assert.False(KnownBenignExceptions.IsMcpClientTransportSendFailure(exception));
        Assert.False(KnownBenignExceptions.IsMcpClientTransportSendFailure(new AggregateException(exception)));
    }

    [Theory]
    [MemberData(nameof(PredicateCases))]
    public void IsMcpClientTransportSendFailure_MatchesExpected(string caseName, Exception? exception, bool expected)
    {
        Assert.True(
            expected == KnownBenignExceptions.IsMcpClientTransportSendFailure(exception),
            $"Case '{caseName}' expected benign={expected}.");
    }

    public static IEnumerable<object?[]> PredicateCases()
    {
        yield return ["null", null, false];

        // The exact #2258 shape: finalizer-thread AggregateException around the 502.
        yield return [
            "streamable-http 502 in aggregate",
            new AggregateException(new FakeHttpRequestException("502 (Bad Gateway)", StreamableHttpSendStack)),
            true];

        yield return [
            "streamable-http 502 bare",
            new FakeHttpRequestException("502 (Bad Gateway)", StreamableHttpSendStack),
            true];

        yield return [
            "sse cancelled-notification IOException",
            new AggregateException(new FakeIOException("connection reset", SseCancelledNotificationStack)),
            true];

        yield return [
            "stdio send TaskCanceledException",
            new AggregateException(new FakeTaskCanceledException(StdioSendStack)),
            true];

        yield return [
            "nested aggregate",
            new AggregateException(new AggregateException(
                new FakeHttpRequestException("502 (Bad Gateway)", StreamableHttpSendStack))),
            true];

        // Right frames, wrong exception type: a daemon bug surfaced through the SDK.
        yield return [
            "InvalidOperationException with MCP frames",
            new AggregateException(new FakeInvalidOperationException(StreamableHttpSendStack)),
            false];

        yield return [
            "transport frame without session handler frame",
            new AggregateException(new FakeHttpRequestException("502 (Bad Gateway)", TransportOnlyStack)),
            false];

        yield return [
            "HttpRequestException without stack",
            new AggregateException(new FakeHttpRequestException("502 (Bad Gateway)", stackTrace: null)),
            false];

        // One MCP failure and one real bug in the same aggregate: keep the crash report.
        yield return [
            "mixed aggregate",
            new AggregateException(
                new FakeHttpRequestException("502 (Bad Gateway)", StreamableHttpSendStack),
                new InvalidOperationException("daemon bug")),
            false];
    }

    private static Exception CaptureThrown(Action action)
    {
        try
        {
            action();
        }
        catch (Exception ex)
        {
            return ex;
        }

        throw new InvalidOperationException("Expected the action to throw.");
    }

    private sealed class FakeHttpRequestException(string message, string? stackTrace) : HttpRequestException(message)
    {
        public override string? StackTrace => stackTrace;
    }

    private sealed class FakeIOException(string message, string? stackTrace) : IOException(message)
    {
        public override string? StackTrace => stackTrace;
    }

    private sealed class FakeTaskCanceledException(string? stackTrace) : TaskCanceledException
    {
        public override string? StackTrace => stackTrace;
    }

    private sealed class FakeInvalidOperationException(string? stackTrace) : InvalidOperationException
    {
        public override string? StackTrace => stackTrace;
    }
}
