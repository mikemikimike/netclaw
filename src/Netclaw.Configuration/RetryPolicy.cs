// -----------------------------------------------------------------------
// <copyright file="RetryPolicy.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Net;
using System.Net.Sockets;

namespace Netclaw.Configuration;

/// <summary>
/// Configuration for retry behavior on transient LLM provider failures.
/// </summary>
public sealed record RetryPolicy
{
    public int MaxRetries { get; init; } = 3;
    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Determines whether the given exception is transient and should be retried.
    /// The exception and its <see cref="Exception.InnerException"/> chain are
    /// classified in this order:
    /// <list type="number">
    /// <item>An HTTP status carried by the outermost status-bearing exception
    /// (<see cref="ProviderException"/> or <see cref="HttpRequestException"/>) is
    /// authoritative: 408/429/5xx retry, anything else does not, regardless of what
    /// transport exception sits underneath.</item>
    /// <item>Status-less <see cref="HttpRequestException"/>s (connection-level failures)
    /// and timeout-style cancellations retry.</item>
    /// <item>An <see cref="HttpIOException"/> (thrown while reading a response body, e.g.
    /// a stream that "ended prematurely") retries only for
    /// <see cref="HttpRequestError.ResponseEnded"/> or
    /// <see cref="HttpRequestError.ConnectionError"/>; other codes describe a malformed
    /// or rejected exchange and never retry, even over a socket error.</item>
    /// <item>Otherwise a <see cref="SocketException"/> anywhere in the chain (e.g. a
    /// connection reset surfacing as a plain <see cref="IOException"/> mid-read) retries.</item>
    /// </list>
    /// Other <see cref="IOException"/>s are deliberately not treated as transient.
    /// <para>
    /// SDK result exceptions (e.g. System.ClientModel's <c>ClientResultException</c> from
    /// the OpenAI SDK) are deliberately not recognized here. One that carries an HTTP
    /// status is the end of the SDK pipeline's own retry loop (which already retried
    /// 408/429/5xx, honoring <c>Retry-After</c>); retrying it again would multiply
    /// requests and delay failover. One without a response wraps the transport exception
    /// that caused it, which the rules above classify.
    /// </para>
    /// Only <see cref="Exception.InnerException"/> is followed: the members of an
    /// <see cref="AggregateException"/> beyond its first inner exception are not inspected.
    /// </summary>
    public bool ShouldRetry(Exception ex, int attempt)
    {
        if (attempt >= MaxRetries)
            return false;

        // Curated provider errors (e.g. the self-hosted OpenAI-compatible client) carry
        // the HTTP status on a ProviderException rather than a raw HttpRequestException,
        // possibly nested under other exceptions. The outermost status wins so that,
        // e.g., a 400 wrapping a dropped connection is not retried.
        if (FindStatus(ex) is { } status)
            return status.IsTransient;

        if (FindInner<HttpRequestException>(ex) is { StatusCode: null })
            return true;

        if (ex is TaskCanceledException or TimeoutException)
            return true;

        // A streaming response cut off by the network ("The response ended prematurely.
        // (ResponseEnded)") surfaces as HttpIOException while reading the body. Its error
        // code is authoritative for the SocketException check below.
        if (FindInner<HttpIOException>(ex) is { } ioEx)
            return ioEx.HttpRequestError is HttpRequestError.ResponseEnded or HttpRequestError.ConnectionError;

        return FindInner<SocketException>(ex) is not null;
    }

    private readonly record struct HttpStatus(bool IsTransient);

    private static HttpStatus? FindStatus(Exception? ex)
    {
        for (; ex is not null; ex = ex.InnerException)
        {
            switch (ex)
            {
                case ProviderException { StatusCode: { } providerStatus }:
                    return new HttpStatus(IsTransientProviderStatus(providerStatus));
                case HttpRequestException { StatusCode: { } httpStatus }:
                    return new HttpStatus(httpStatus is
                        HttpStatusCode.RequestTimeout or
                        HttpStatusCode.TooManyRequests or
                        HttpStatusCode.InternalServerError or
                        HttpStatusCode.BadGateway or
                        HttpStatusCode.ServiceUnavailable or
                        HttpStatusCode.GatewayTimeout);
            }
        }

        return null;
    }

    private static bool IsTransientProviderStatus(int status) =>
        status is 408 or 429 or (>= 500 and <= 599);

    private static T? FindInner<T>(Exception? ex) where T : Exception
    {
        while (ex is not null)
        {
            if (ex is T match)
                return match;
            ex = ex.InnerException;
        }

        return null;
    }

    /// <summary>
    /// Returns the delay before the next retry attempt using exponential backoff with jitter.
    /// </summary>
    public TimeSpan GetDelay(int attempt)
    {
        var exponential = TimeSpan.FromTicks(BaseDelay.Ticks * (1L << attempt));
        var capped = exponential > MaxDelay ? MaxDelay : exponential;
        // Add ±25% jitter to avoid thundering herd
        var jitter = 0.75 + Random.Shared.NextDouble() * 0.5;
        return TimeSpan.FromTicks((long)(capped.Ticks * jitter));
    }
}
