// -----------------------------------------------------------------------
// <copyright file="RetryPolicyTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.ClientModel;
using System.Net.Sockets;
using Xunit;

namespace Netclaw.Configuration.Tests;

public sealed class RetryPolicyTests
{
    private readonly RetryPolicy _policy = new() { MaxRetries = 3 };

    public static TheoryData<string, Func<Exception>> TransientStreamTruncationCases { get; } = new()
    {
        {
            "ResponseEnded",
            () => new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely. (ResponseEnded)")
        },
        {
            "ConnectionError",
            () => new HttpIOException(HttpRequestError.ConnectionError, "connection lost")
        },
        {
            "ResponseEnded wrapped by an SDK ClientResultException",
            () => new ClientResultException("service request failed",
                innerException: new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely."))
        },
        {
            "ResponseEnded wrapped in a ProviderException without a status",
            () => new ProviderException("stream dropped", "ResponseEnded",
                innerException: new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely."))
        },
        {
            "Connection reset surfacing as IOException over SocketException",
            () => new IOException("Unable to read data from the transport connection.",
                new SocketException((int)SocketError.ConnectionReset))
        }
    };

    [Theory]
    [MemberData(nameof(TransientStreamTruncationCases))]
    public void ShouldRetry_TransportStreamTruncation(string name, Func<Exception> makeException)
    {
        Assert.True(_policy.ShouldRetry(makeException(), attempt: 0), $"case '{name}' should be retried");
    }

    public static TheoryData<string, Func<Exception>> NonTransientIoCases { get; } = new()
    {
        {
            "InvalidResponse",
            () => new HttpIOException(HttpRequestError.InvalidResponse, "malformed chunked encoding")
        },
        {
            "Plain IOException",
            () => new IOException("disk full")
        },
        {
            "FileNotFoundException",
            () => new FileNotFoundException("missing")
        }
    };

    [Theory]
    [MemberData(nameof(NonTransientIoCases))]
    public void ShouldNotRetry_NonTransientIoFailures(string name, Func<Exception> makeException)
    {
        Assert.False(_policy.ShouldRetry(makeException(), attempt: 0), $"case '{name}' should not be retried");
    }

    [Fact]
    public void ShouldNotRetry_ResponseEnded_WhenRetriesExhausted()
    {
        var ex = new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely.");

        Assert.False(_policy.ShouldRetry(ex, attempt: _policy.MaxRetries));
    }
}
