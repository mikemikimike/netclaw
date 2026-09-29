// -----------------------------------------------------------------------
// <copyright file="RetryingChatClientTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.Logging.Abstractions;
using Netclaw.Configuration;
using Netclaw.Daemon.Configuration;
using Xunit;

namespace Netclaw.Daemon.Tests.Configuration;

public sealed class RetryingChatClientTests
{
    private readonly RetryPolicy _policy = new()
    {
        MaxRetries = 3,
        BaseDelay = TimeSpan.FromMilliseconds(1),
        MaxDelay = TimeSpan.FromMilliseconds(10)
    };

    // Which exceptions are transient is covered once, in
    // Netclaw.Configuration.Tests.RetryPolicyTests; these tests cover how the decorator
    // applies that decision.
    [Fact]
    public async Task RetriesOnTransientFailure_ThenSucceeds()
    {
        var attempts = 0;
        var fake = new FakeChatClient((_, _, _) =>
        {
            attempts++;
            if (attempts <= 2)
                throw new HttpRequestException("rate limited", null, HttpStatusCode.TooManyRequests);
            return Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "ok")]));
        });

        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);
        var response = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal("ok", response.Messages[0].Text);
        Assert.Equal(3, attempts); // 2 failures + 1 success
    }

    [Fact]
    public async Task StopsAfterMaxRetries()
    {
        var attempts = 0;
        var fake = new FakeChatClient((_,_,_) =>
        {
            attempts++;
            throw new HttpRequestException("always fails", null, HttpStatusCode.TooManyRequests);
        });

        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken));

        // 1 initial + 3 retries = 4 total
        Assert.Equal(4, attempts);
    }

    // NOTE: RetryingChatClient deliberately does NOT open its own SessionId scope — it
    // inherits the enclosing LoggingChatClient scope in the composed pipeline. The retry
    // warning's session correlation is therefore covered by
    // PipelineChatClientFactoryTests.Compose_streaming_retry_warning_inherits_SessionId_scope,
    // which exercises the real composition, not this decorator in isolation.

    [Fact]
    public async Task DoesNotRetryNonTransientErrors()
    {
        var attempts = 0;
        var fake = new FakeChatClient((_,_,_) =>
        {
            attempts++;
            throw new HttpRequestException("bad request", null, HttpStatusCode.BadRequest);
        });

        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal(1, attempts); // No retries for 400
    }

    [Fact]
    public async Task DoesNotRetry_WhenCancelled()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        var attempts = 0;
        var fake = new FakeChatClient((_,_,_) =>
        {
            attempts++;
            throw new HttpRequestException("server error", null, HttpStatusCode.InternalServerError);
        });

        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        // Should propagate the exception without retrying since CT is already cancelled
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.User, "hi")], cancellationToken: cts.Token));

        Assert.Equal(1, attempts); // No retries when cancelled
    }

    [Fact]
    public async Task StreamingRetriesPreFirstChunk_ThenSucceeds()
    {
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return ThrowBeforeChunkThenYield(attempts, failUntil: 3, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }

        Assert.Single(updates);     // only the successful attempt yields
        Assert.Equal(3, attempts);  // 2 pre-chunk failures + 1 success, each re-initiates the stream
    }

    [Fact]
    public async Task StreamingDoesNotRetryAfterFirstChunk()
    {
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return YieldThenThrow(ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await Assert.ThrowsAsync<HttpRequestException>(async () =>
        {
            await foreach (var u in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
            {
                updates.Add(u);
            }
        });

        // The 500 is retryable by policy, but a chunk was already emitted, so the
        // failure propagates instead of restarting (no duplicate output).
        Assert.Single(updates);
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task StreamingStopsAfterMaxRetries()
    {
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return ThrowBeforeChunkThenYield(attempts, failUntil: 100, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        await Assert.ThrowsAsync<HttpRequestException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken)) { }
        });

        Assert.Equal(4, attempts); // 1 initial + 3 retries
    }

    [Fact]
    public async Task StreamingDoesNotRetry_WhenCancelled()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return ThrowBeforeChunkThenYield(attempts, failUntil: 100, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var _ in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hi")], cancellationToken: cts.Token)) { }
        });

        Assert.Equal(1, attempts); // cancellation is not retried
    }

    [Fact]
    public async Task StreamingRetries_ProviderException5xx_ThenSucceeds()
    {
        // Curated provider errors carry the status on a ProviderException, not a raw
        // HttpRequestException — the transport must still recognize them as transient.
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return ThrowProviderExceptionThenYield(attempts, failUntil: 3, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }

        Assert.Single(updates);
        Assert.Equal(3, attempts); // 2 ProviderException(502) failures + 1 success
    }

    [Fact]
    public async Task StreamingRetries_ResponseEndedBeforeFirstChunk_ThenSucceeds()
    {
        // #2262: a dropped stream surfaces as HttpIOException(ResponseEnded) while reading
        // the body. Before the first chunk nothing has been emitted, so it must be retried
        // rather than failing the turn.
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return ThrowResponseEndedThenYield(attempts, failUntil: 2, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }

        var update = Assert.Single(updates);
        Assert.Equal("ok", update.Text);
        Assert.Equal(2, attempts); // 1 ResponseEnded failure + 1 success
    }

    [Fact]
    public async Task StreamingDoesNotRetry_ResponseEndedAfterFirstChunk()
    {
        // Mid-stream truncation is out of scope for the retry decorator: restarting would
        // duplicate the chunk already emitted downstream.
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return YieldThenThrowResponseEnded(ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        var ex = await Assert.ThrowsAsync<HttpIOException>(async () =>
        {
            await foreach (var u in client.GetStreamingResponseAsync(
                [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
            {
                updates.Add(u);
            }
        });

        Assert.Equal(HttpRequestError.ResponseEnded, ex.HttpRequestError);
        Assert.Single(updates);
        Assert.Equal(1, attempts);
    }

    [Fact]
    public async Task StreamingRetries_ResponseEndedAfterLifecycleUpdates_WithoutLeakingFailedAttempt()
    {
        // #2262: OpenAIResponsesChatClient yields content-free updates for
        // response.created / in_progress / output_item.added as soon as headers arrive.
        // Those must not commit the stream, and none of the failed attempt's ids may
        // reach the aggregated response.
        var attempts = 0;
        var fake = new FakeChatClient(streamHandler: (_, _, ct) =>
        {
            attempts++;
            return LifecycleThenResponseEndedOrText($"resp_{attempts}", fail: attempts == 1, ct);
        });
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }

        Assert.Equal(2, attempts);
        Assert.DoesNotContain(updates, u => u.ResponseId == "resp_1" || u.MessageId == "msg_resp_1");

        var response = updates.ToChatResponse();
        var message = Assert.Single(response.Messages);
        Assert.Equal("ok", message.Text);
        Assert.Equal("msg_resp_2", message.MessageId);
        Assert.Equal("resp_2", response.ResponseId);
    }

    [Fact]
    public async Task Streaming_MetadataOnlyStream_ReleasesHeldUpdatesOnCompletion()
    {
        var created = new ChatResponseUpdate { ResponseId = "resp_1", MessageId = "msg_1", Role = ChatRole.Assistant };
        var fake = new FakeChatClient(streamHandler: (_, _, ct) => YieldOnly(created, ct));
        var client = new RetryingChatClient(fake, _policy, NullLogger.Instance);

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in client.GetStreamingResponseAsync(
            [new ChatMessage(ChatRole.User, "hi")], cancellationToken: TestContext.Current.CancellationToken))
        {
            updates.Add(u);
        }

        Assert.Contains(created, updates);
        Assert.Equal("resp_1", updates.ToChatResponse().ResponseId);
    }

    private static async IAsyncEnumerable<ChatResponseUpdate> LifecycleThenResponseEndedOrText(
        string responseId, bool fail,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        yield return new ChatResponseUpdate { ResponseId = responseId, Role = ChatRole.Assistant };
        yield return new ChatResponseUpdate { ResponseId = responseId, MessageId = "msg_" + responseId, Role = ChatRole.Assistant };
        if (fail)
            throw new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely. (ResponseEnded)");

        yield return new ChatResponseUpdate
        {
            ResponseId = responseId,
            MessageId = "msg_" + responseId,
            Role = ChatRole.Assistant,
            Contents = [new TextContent("ok")]
        };
    }

    private static async IAsyncEnumerable<ChatResponseUpdate> YieldOnly(
        ChatResponseUpdate update, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        yield return update;
    }

    private static async IAsyncEnumerable<ChatResponseUpdate> ThrowResponseEndedThenYield(
        int attemptNumber, int failUntil,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        if (attemptNumber < failUntil)
            throw new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely. (ResponseEnded)");

        yield return new ChatResponseUpdate { Role = ChatRole.Assistant, Contents = [new TextContent("ok")] };
    }

    private static async IAsyncEnumerable<ChatResponseUpdate> YieldThenThrowResponseEnded(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        yield return new ChatResponseUpdate { Role = ChatRole.Assistant, Contents = [new TextContent("partial")] };
        throw new HttpIOException(HttpRequestError.ResponseEnded, "The response ended prematurely. (ResponseEnded)");
    }

    // Throws a retryable 429 before yielding any chunk while attemptNumber < failUntil,
    // otherwise yields one chunk. The runtime-dependent condition keeps the yield
    // reachable (no CS0162) so no warning suppression is needed.
    private static async IAsyncEnumerable<ChatResponseUpdate> ThrowBeforeChunkThenYield(
        int attemptNumber, int failUntil,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        if (attemptNumber < failUntil)
            throw new HttpRequestException("rate limited", null, HttpStatusCode.TooManyRequests);

        yield return new ChatResponseUpdate { Role = ChatRole.Assistant, Contents = [new TextContent("ok")] };
    }

    // Same shape as ThrowBeforeChunkThenYield but throws a curated ProviderException(502).
    private static async IAsyncEnumerable<ChatResponseUpdate> ThrowProviderExceptionThenYield(
        int attemptNumber, int failUntil,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        if (attemptNumber < failUntil)
            throw new ProviderException("server error (502)", "HTTP 502", statusCode: 502);

        yield return new ChatResponseUpdate { Role = ChatRole.Assistant, Contents = [new TextContent("ok")] };
    }

    private static async IAsyncEnumerable<ChatResponseUpdate> YieldThenThrow(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        yield return new ChatResponseUpdate { Role = ChatRole.Assistant, Contents = [new TextContent("partial")] };
        throw new HttpRequestException("mid-stream failure", null, HttpStatusCode.InternalServerError);
    }
}

/// <summary>
/// Minimal IChatClient test double.
/// </summary>
internal sealed class FakeChatClient : IChatClient
{
    private readonly Func<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken, Task<ChatResponse>>? _handler;
    private readonly Func<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken, IAsyncEnumerable<ChatResponseUpdate>>? _streamHandler;

    public FakeChatClient(
        Func<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken, Task<ChatResponse>>? handler = null,
        bool streaming = false,
        Func<IEnumerable<ChatMessage>, ChatOptions?, CancellationToken, IAsyncEnumerable<ChatResponseUpdate>>? streamHandler = null)
    {
        _ = streaming;
        _handler = handler;
        _streamHandler = streamHandler;
    }

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (_handler is not null)
            return _handler(messages, options, cancellationToken);

        return Task.FromResult(new ChatResponse([new ChatMessage(ChatRole.Assistant, "default")]));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (_streamHandler is not null)
            return _streamHandler(messages, options, cancellationToken);

        return StreamAsync();
    }

    private async IAsyncEnumerable<ChatResponseUpdate> StreamAsync()
    {
        await Task.CompletedTask;
        yield return new ChatResponseUpdate
        {
            Role = ChatRole.Assistant,
            Contents = [new TextContent("streamed")]
        };
    }

    public object? GetService(Type serviceType, object? serviceKey = null) => null;
    public void Dispose() { }
}
