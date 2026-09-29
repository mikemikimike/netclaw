// -----------------------------------------------------------------------
// <copyright file="StreamCommitGateTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Microsoft.Extensions.AI;
using Netclaw.Configuration;
using Netclaw.Daemon.Configuration;
using Xunit;

namespace Netclaw.Daemon.Tests.Configuration;

public sealed class StreamCommitGateTests
{
    private static ChatResponseUpdate Lifecycle(string responseId) =>
        new() { ResponseId = responseId, MessageId = "msg_" + responseId, Role = ChatRole.Assistant };

    private static ChatResponseUpdate Text(string text) =>
        new() { Role = ChatRole.Assistant, Contents = [new TextContent(text)] };

    [Fact]
    public void Lifecycle_update_is_held_and_replaced_by_an_information_free_keepalive()
    {
        var gate = new StreamCommitGate();
        var created = Lifecycle("r1");

        var emitted = gate.Accept(created);

        var keepalive = Assert.Single(emitted);
        Assert.NotSame(created, keepalive);
        Assert.True(ChatStreamUpdates.CarriesNoInformation(keepalive));
        Assert.False(gate.Committed);
    }

    [Fact]
    public void First_substantive_update_commits_and_releases_held_updates_in_order()
    {
        var gate = new StreamCommitGate();
        var created = Lifecycle("r1");
        var usage = new ChatResponseUpdate { Contents = [new UsageContent(new UsageDetails { InputTokenCount = 3 })] };
        var text = Text("hello");

        gate.Accept(created);
        gate.Accept(usage);
        var emitted = gate.Accept(text);

        Assert.True(gate.Committed);
        Assert.Equal([created, usage, text], emitted);
        Assert.Equal([text], gate.Accept(text)); // committed: pass-through
    }

    [Fact]
    public void Information_free_update_passes_through_without_being_held()
    {
        // e.g. the keepalive emitted by an inner gate: holding it would only duplicate
        // empty updates downstream when the outer gate commits.
        var gate = new StreamCommitGate();
        var keepalive = new ChatResponseUpdate();

        Assert.Equal([keepalive], gate.Accept(keepalive));
        var text = Text("x");
        Assert.Equal([text], gate.Accept(text)); // nothing was held ahead of it
    }

    [Fact]
    public void Complete_releases_held_updates_when_nothing_substantive_arrived()
    {
        var gate = new StreamCommitGate();
        var created = Lifecycle("r1");
        gate.Accept(created);

        var released = gate.Complete();

        Assert.Equal([created], released);
        Assert.True(gate.Committed);
    }
}
