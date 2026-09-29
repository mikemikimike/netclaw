// -----------------------------------------------------------------------
// <copyright file="ChatStreamUpdatesTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Microsoft.Extensions.AI;
using Xunit;

namespace Netclaw.Configuration.Tests;

public sealed class ChatStreamUpdatesTests
{
    public static TheoryData<string, Func<ChatResponseUpdate>, bool> SubstantiveCases { get; } = new()
    {
        { "text", () => new ChatResponseUpdate { Contents = [new TextContent("hi")] }, true },
        { "reasoning", () => new ChatResponseUpdate { Contents = [new TextReasoningContent("thinking")] }, true },
        { "tool call", () => new ChatResponseUpdate { Contents = [new FunctionCallContent("c1", "tool")] }, true },
        { "finish reason only", () => new ChatResponseUpdate { FinishReason = ChatFinishReason.Stop }, true },
        { "unknown content", () => new ChatResponseUpdate { Contents = [new ErrorContent("refused")] }, true },
        { "empty text", () => new ChatResponseUpdate { Contents = [new TextContent("")] }, false },
        { "usage only", () => new ChatResponseUpdate { Contents = [new UsageContent(new UsageDetails { InputTokenCount = 5 })] }, false },
        {
            "response.created-style lifecycle update",
            () => new ChatResponseUpdate { ResponseId = "resp_1", MessageId = "msg_1", ModelId = "gpt", Role = ChatRole.Assistant },
            false
        }
    };

    [Theory]
    [MemberData(nameof(SubstantiveCases))]
    public void IsSubstantive(string name, Func<ChatResponseUpdate> makeUpdate, bool expected)
    {
        Assert.True(ChatStreamUpdates.IsSubstantive(makeUpdate()) == expected, $"case '{name}' expected {expected}");
    }

    [Fact]
    public void CarriesNoInformation_OnlyForAnEmptyUpdate()
    {
        Assert.True(ChatStreamUpdates.CarriesNoInformation(new ChatResponseUpdate()));
        Assert.False(ChatStreamUpdates.CarriesNoInformation(new ChatResponseUpdate { ResponseId = "resp_1" }));
        Assert.False(ChatStreamUpdates.CarriesNoInformation(new ChatResponseUpdate { Role = ChatRole.Assistant }));
        Assert.False(ChatStreamUpdates.CarriesNoInformation(new ChatResponseUpdate { RawRepresentation = new object() }));
        Assert.False(ChatStreamUpdates.CarriesNoInformation(
            new ChatResponseUpdate { AdditionalProperties = new AdditionalPropertiesDictionary { ["k"] = "v" } }));
    }
}
