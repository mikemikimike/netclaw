// -----------------------------------------------------------------------
// <copyright file="StreamCommitGate.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Microsoft.Extensions.AI;
using Netclaw.Configuration;

namespace Netclaw.Daemon.Configuration;

/// <summary>
/// Decides, for one streaming attempt, which updates may be emitted downstream and
/// when the stream becomes <b>committed</b> (no longer safe to restart or fail over).
/// Shared by <see cref="RetryingChatClient"/> and <see cref="RoutingChatClient"/>.
/// <para>
/// Some SDKs emit content-free lifecycle updates the moment response headers arrive
/// (e.g. <c>OpenAIResponsesChatClient</c> yields an empty update for
/// <c>response.created</c>/<c>in_progress</c>/<c>output_item.added</c>). If those
/// committed the stream, a connection dropped before the first token could never be
/// retried. They also carry ids (<see cref="ChatResponseUpdate.ResponseId"/>,
/// <see cref="ChatResponseUpdate.MessageId"/>, ...) that downstream
/// <c>ToChatResponse()</c> folds into the final response, so forwarding a failed
/// attempt's copies and then the retry's would leave stale ids and split an empty
/// assistant message off the real one.
/// </para>
/// <para>
/// So until the first substantive update (<see cref="ChatStreamUpdates.IsSubstantive"/>),
/// an update carrying metadata is <b>held</b> and replaced downstream by an
/// information-free keepalive; the session watchdog still sees liveness during a long
/// prefill, but nothing from a failed attempt reaches the final response. The first
/// substantive update commits the stream and releases the held updates, in order,
/// ahead of it. An attempt that fails before committing is simply discarded along with
/// its gate. A stream that completes without ever committing releases its held updates
/// via <see cref="Complete"/>.
/// </para>
/// </summary>
internal sealed class StreamCommitGate
{
    private readonly List<ChatResponseUpdate> _held = [];

    /// <summary>
    /// True once a substantive update has been emitted downstream; from then on a
    /// failure must propagate rather than restart the stream.
    /// </summary>
    public bool Committed { get; private set; }

    /// <summary>Returns the updates to emit downstream for <paramref name="update"/>.</summary>
    public IReadOnlyList<ChatResponseUpdate> Accept(ChatResponseUpdate update)
    {
        if (Committed)
            return [update];

        if (ChatStreamUpdates.IsSubstantive(update))
        {
            Committed = true;
            _held.Add(update);
            var released = _held.ToArray();
            _held.Clear();
            return released;
        }

        // Pure liveness (including another gate's keepalive): nothing to hold back.
        if (ChatStreamUpdates.CarriesNoInformation(update))
            return [update];

        _held.Add(update);
        return [new ChatResponseUpdate()];
    }

    /// <summary>
    /// Called when the attempt's stream ends cleanly; returns any held updates so a
    /// response with no substantive update (e.g. metadata only) is not lost.
    /// </summary>
    public IReadOnlyList<ChatResponseUpdate> Complete()
    {
        Committed = true;
        var released = _held.ToArray();
        _held.Clear();
        return released;
    }
}
