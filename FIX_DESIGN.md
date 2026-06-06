# Design Document: Fix WebView2 Process Spawn Leak

## Problem
The current implementation of `AutoEnforce` in both the CLI (`Program.cs`) and Desktop (`NetworkMonitorService.cs`) versions of MyFirewall has a critical design flaw:
1. When an IP address is blocked, the application automatically adds the name of the process that initiated the connection to a "blocked process names" list.
2. The background monitoring loop (running every 3 seconds) scans all active system processes. If any process name matches the "blocked" list, it is immediately terminated.
3. For shared or system-critical processes like `msedgewebview2` (WebView2), Windows or the parent application immediately respawns the process.
4. This results in a "kill-loop" where thousands of processes are spawned and killed per hour, causing high CPU usage and system instability.

## Proposed Solution
Decouple **IP Blocking** (Network layer) from **Process Killing** (Application layer).

### Changes in `Program.cs` (CLI)
1.  **Refactor `RebuildBlockedProcessNames`**: Stop automatically adding process names to `_blockedProcessNames` based on blocked IP entries.
2.  **Refactor `AutoEnforceBlockRules`**: Remove the loop that iterates through `Process.GetProcesses()` to kill processes.
3.  **Preserve Explicit Killing**: Keep the `KillProcessInteractive` command ('K' key) so users can still manually terminate processes if desired.

### Changes in `MyFirewall.Desktop`
1.  **Refactor `MainViewModel.RebuildBlockedProcessNames`**: Similar to the CLI version, prevent automatic process name blocking.
2.  **Refactor `NetworkMonitorService.AutoEnforce`**: Remove the auto-kill loop that uses `Process.GetProcesses()`.
3.  **Preserve Manual Control**: Keep the `StopAppCommand` in the UI context menu for manual termination.

## Impact Analysis
- **Security**: The application will still effectively block network traffic to/from restricted IPs via the Windows Firewall.
- **Stability**: Resolves the "thousands of spawns" issue by allowing processes to remain running while their network access is restricted.
- **User Experience**: Prevents unintended termination of shared components (like Edge or WebView2) that might be used by multiple applications.

## Verification Plan
1.  **Manual Verification**: Verify that blocking an IP correctly adds a Windows Firewall rule.
2.  **Process Monitoring**: Verify that the associated process is *not* terminated automatically after blocking an IP.
3.  **Regression Testing**: Ensure manual "Kill" and "Stop App" features still function correctly.
