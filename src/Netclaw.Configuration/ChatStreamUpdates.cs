// -----------------------------------------------------------------------
// <copyright file="ChatStreamUpdates.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Microsoft.Extensions.AI;

namespace Netclaw.Configuration;

/// <summary>
/// The single definition of whether a streaming <see cref="ChatResponseUpdate"/> is real
/// model progress, shared by the session stream reader (watchdog promotion) and the
/// retry/failover decorators (when a stream commits and can no longer be restarted).
/// </summary>
public static class ChatStreamUpdates
{
    /// <summary>
    /// True when an update represents real model progress. A finish reason, non-empty
    /// text/thinking, a tool call, or any non-usage content all count. Only a
    /// content-free update (a heartbeat, or the empty lifecycle updates some SDKs emit
    /// for events like <c>response.created</c>) or a usage-only chunk with no finish
    /// reason is non-substantive, as are empty text/thinking deltas that carry no
    /// protected data. Unknown content counts as substantive so a provider
    /// that streams an error/refusal or other non-text content is never mistaken for a
    /// hang, and is never silently re-requested.
    /// </summary>
    public static bool IsSubstantive(ChatResponseUpdate update)
    {
        if (update.FinishReason is not null)
            return true;

        foreach (var content in update.Contents)
        {
            switch (content)
            {
                case TextContent text when !string.IsNullOrEmpty(text.Text):
                case TextReasoningContent reasoning when !string.IsNullOrEmpty(reasoning.Text):
                // Text-less reasoning that carries protected data (an Anthropic thinking
                // signature / redacted thinking, or encrypted reasoning) is real model
                // output that must round-trip to the provider, not a heartbeat.
                case TextReasoningContent { ProtectedData.Length: > 0 }:
                case FunctionCallContent:
                    return true;
                // Empty text/thinking deltas (e.g. a role-only first chunk) carry no
                // output; without these cases they would fall through to default.
                case TextContent:
                case TextReasoningContent:
                case UsageContent:
                    break;
                default:
                    return true;
            }
        }

        return false;
    }
}
