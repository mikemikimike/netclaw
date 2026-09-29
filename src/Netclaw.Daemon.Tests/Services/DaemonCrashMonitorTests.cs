// -----------------------------------------------------------------------
// <copyright file="DaemonCrashMonitorTests.cs" company="Petabridge, LLC">
//      Copyright (C) 2026 - 2026 Petabridge, LLC <https://petabridge.com>
// </copyright>
// -----------------------------------------------------------------------
using Netclaw.Configuration;
using Netclaw.Daemon.Services;
using Xunit;

namespace Netclaw.Daemon.Tests.Services;

public sealed class DaemonCrashMonitorTests : IDisposable
{
    private readonly NetclawPaths _paths =
        new(Path.Combine(Path.GetTempPath(), "netclaw-crash-monitor-" + Guid.NewGuid().ToString("N")));

    public void Dispose()
    {
        if (Directory.Exists(_paths.BasePath))
            Directory.Delete(_paths.BasePath, recursive: true);
    }

    [Fact]
    public async Task Benign_mcp_send_failure_writes_no_crash_log()
    {
        var mcpFailure = await KnownBenignExceptionsTests.CaptureSdkNotificationSendFailureAsync();
        using var monitor = DaemonCrashMonitor.Register(
            _paths,
            benignUnobservedFilters: [KnownBenignExceptions.IsMcpSessionSendFailure]);
        var args = new UnobservedTaskExceptionEventArgs(new AggregateException(mcpFailure));

        monitor.HandleUnobservedTaskException(null, args);

        Assert.True(args.Observed);
        Assert.Empty(CrashLogsContaining(mcpFailure.Message));
    }

    [Fact]
    public void Non_matching_unobserved_exception_writes_crash_log()
    {
        var marker = "daemon bug " + Guid.NewGuid().ToString("N");
        using var monitor = DaemonCrashMonitor.Register(
            _paths,
            benignUnobservedFilters: [KnownBenignExceptions.IsMcpSessionSendFailure]);
        var args = new UnobservedTaskExceptionEventArgs(
            new AggregateException(new HttpRequestException(marker)));

        monitor.HandleUnobservedTaskException(null, args);

        Assert.True(args.Observed);
        var crashLog = Assert.Single(CrashLogsContaining(marker));
        Assert.Contains("daemon-unobserved", File.ReadAllText(crashLog));
    }

    // Match by content: the monitor subscribes to process-wide events, so an unrelated
    // unobserved exception from a parallel test can also write into this directory.
    private IEnumerable<string> CrashLogsContaining(string marker)
        => Directory.Exists(_paths.LogsDirectory)
            ? Directory.EnumerateFiles(_paths.LogsDirectory, "crash-*.log")
                .Where(path => File.ReadAllText(path).Contains(marker, StringComparison.Ordinal))
                .ToList()
            : [];
}
