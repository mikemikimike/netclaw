// -----------------------------------------------------------------------
// <copyright file="RetryPolicyTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.ClientModel;
using System.ClientModel.Primitives;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Netclaw.Configuration.Tests;

/// <summary>
/// The single home for <see cref="RetryPolicy.ShouldRetry"/> exception classification.
/// Decorator tests (RetryingChatClientTests, RoutingChatClientTests) cover how the
/// decision is applied, not which exceptions are transient.
/// </summary>
public sealed class RetryPolicyTests
{
    private readonly RetryPolicy _policy = new() { MaxRetries = 3 };

    private static HttpIOException ResponseEnded() =>
        new(HttpRequestError.ResponseEnded, "The response ended prematurely. (ResponseEnded)");

    private static SocketException ConnectionReset() => new((int)SocketError.ConnectionReset);

    public static TheoryData<string, Func<Exception>> TransientCases { get; } = new()
    {
        // HTTP status responses
        { "HttpRequestException 408", () => new HttpRequestException("timeout", null, HttpStatusCode.RequestTimeout) },
        { "HttpRequestException 429", () => new HttpRequestException("rate limited", null, HttpStatusCode.TooManyRequests) },
        { "HttpRequestException 500", () => new HttpRequestException("server error", null, HttpStatusCode.InternalServerError) },
        { "HttpRequestException 503", () => new HttpRequestException("unavailable", null, HttpStatusCode.ServiceUnavailable) },
        { "ProviderException 502", () => new ProviderException("server error (502)", "HTTP 502", statusCode: 502) },
        { "ProviderException 429 nested", () => new InvalidOperationException("wrapped", new ProviderException("rate limited", "HTTP 429", statusCode: 429)) },

        // Connection-level and timeout failures
        { "Status-less HttpRequestException", () => new HttpRequestException("connection refused") },
        { "Status-less HttpRequestException wrapped by ClientResultException", () => new ClientResultException("request failed", innerException: new HttpRequestException("connection refused")) },
        { "TaskCanceledException (timeout)", () => new TaskCanceledException("request timed out") },
        { "TimeoutException", () => new TimeoutException("stream idle") },

        // #2262: transport-level stream truncation
        { "HttpIOException ResponseEnded", ResponseEnded },
        { "HttpIOException ConnectionError", () => new HttpIOException(HttpRequestError.ConnectionError, "connection lost") },
        { "ResponseEnded wrapped by ClientResultException without a response", () => new ClientResultException("service request failed", innerException: ResponseEnded()) },
        { "ResponseEnded wrapped by a status-less ProviderException", () => new ProviderException("stream dropped", "ResponseEnded", innerException: ResponseEnded()) },
        { "Connection reset as IOException over SocketException", () => new IOException("Unable to read data from the transport connection.", ConnectionReset()) },
        { "Connection reset nested deeper in the chain", () => new InvalidOperationException("wrapped", new IOException("read failed", ConnectionReset())) }
    };

    [Theory]
    [MemberData(nameof(TransientCases))]
    public void ShouldRetry_TransientFailures(string name, Func<Exception> makeException)
    {
        Assert.True(_policy.ShouldRetry(makeException(), attempt: 0), $"case '{name}' should be retried");
    }

    public static TheoryData<string, Func<Exception>> NonTransientCases { get; } = new()
    {
        { "HttpRequestException 400", () => new HttpRequestException("bad request", null, HttpStatusCode.BadRequest) },
        { "HttpRequestException 401", () => new HttpRequestException("unauthorized", null, HttpStatusCode.Unauthorized) },
        { "ProviderException 400", () => new ProviderException("bad request", "HTTP 400", statusCode: 400) },
        // The SDK pipeline already retried these (honoring Retry-After); retrying again
        // would multiply requests and delay failover.
        { "ClientResultException 429 (SDK already retried)", () => new ClientResultException(new StubPipelineResponse(429)) },
        { "ClientResultException 503 (SDK already retried)", () => new ClientResultException(new StubPipelineResponse(503)) },
        { "ClientResultException 400", () => new ClientResultException(new StubPipelineResponse(400)) },
        { "ProviderException 400 over ResponseEnded (status wins)", () => new ProviderException("bad request", "HTTP 400", statusCode: 400, innerException: ResponseEnded()) },
        { "ProviderException 401 over a socket reset", () => new ProviderException("unauthorized", "HTTP 401", statusCode: 401, innerException: new IOException("read failed", ConnectionReset())) },
        { "HttpIOException InvalidResponse", () => new HttpIOException(HttpRequestError.InvalidResponse, "malformed chunked encoding") },
        { "HttpIOException InvalidResponse over a socket reset", () => new HttpIOException(HttpRequestError.InvalidResponse, "malformed", ConnectionReset()) },
        { "Plain IOException", () => new IOException("disk full") },
        { "FileNotFoundException", () => new FileNotFoundException("missing") },
        { "InvalidOperationException", () => new InvalidOperationException("bug") }
    };

    [Theory]
    [MemberData(nameof(NonTransientCases))]
    public void ShouldNotRetry_NonTransientFailures(string name, Func<Exception> makeException)
    {
        Assert.False(_policy.ShouldRetry(makeException(), attempt: 0), $"case '{name}' should not be retried");
    }

    [Fact]
    public void ShouldNotRetry_WhenRetriesExhausted()
    {
        Assert.False(_policy.ShouldRetry(ResponseEnded(), attempt: _policy.MaxRetries));
    }

    /// <summary>Minimal response so a <see cref="ClientResultException"/> carries a status.</summary>
    private sealed class StubPipelineResponse(int status) : PipelineResponse
    {
        public override int Status => status;
        public override string ReasonPhrase => string.Empty;
        public override Stream? ContentStream { get; set; }
        public override BinaryData Content => BinaryData.Empty;
        protected override PipelineResponseHeaders HeadersCore => throw new NotSupportedException();
        public override BinaryData BufferContent(CancellationToken cancellationToken = default) => BinaryData.Empty;
        public override ValueTask<BinaryData> BufferContentAsync(CancellationToken cancellationToken = default) => ValueTask.FromResult(BinaryData.Empty);
        public override void Dispose() { }
    }
}
