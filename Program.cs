using Spectre.Console;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

// ─────────────────────────────────────────────────────────────────────────────
//  Windows Firewall COM interop types  (replaces powershell.exe spawning)
// ─────────────────────────────────────────────────────────────────────────────
[ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), CoClass(typeof(NetFwPolicy2Class))]
interface INetFwPolicy2
{
    [DispId(1)]  int CurrentProfileTypes { get; }
    [DispId(2)]  bool FirewallEnabled { [param: In] set; get; }
    [DispId(3)]  object ExcludedInterfaces { [param: In] set; get; }
    [DispId(4)]  bool BlockAllInboundTraffic { [param: In] set; get; }
    [DispId(5)]  bool NotificationsDisabled { [param: In] set; get; }
    [DispId(6)]  bool UnicastResponsesToMulticastBroadcastDisabled { [param: In] set; get; }
    [DispId(7)]  INetFwRules Rules { get; }
    [DispId(8)]  object ServiceRestriction { get; }
    [DispId(9)]  void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);
    [DispId(10)] bool IsRuleGroupEnabled(int profileTypesBitmask, string group);
    [DispId(11)] void RestoreLocalFirewallDefaults();
    [DispId(12)] object DefaultInboundAction  { [param: In] set; get; }
    [DispId(13)] object DefaultOutboundAction { [param: In] set; get; }
    [DispId(14)] bool IsRuleGroupCurrentlyEnabled(string group);
    [DispId(15)] object LocalPolicyModifyState { get; }
}

[ComImport, Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
class NetFwPolicy2Class { }

[ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
interface INetFwRules : System.Collections.IEnumerable
{
    [DispId(1)]  int Count { get; }
    [DispId(2)]  void Add(INetFwRule rule);
    [DispId(3)]  void Remove(string name);
    [DispId(4)]  INetFwRule Item(string name);
}

[ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2"), CoClass(typeof(NetFwRuleClass))]
interface INetFwRule
{
    [DispId(1)]  string Name          { [param: In] set; get; }
    [DispId(2)]  string Description   { [param: In] set; get; }
    [DispId(3)]  string ApplicationName { [param: In] set; get; }
    [DispId(4)]  string serviceName   { [param: In] set; get; }
    [DispId(5)]  int    Protocol      { [param: In] set; get; }
    [DispId(6)]  string LocalPorts    { [param: In] set; get; }
    [DispId(7)]  string RemotePorts   { [param: In] set; get; }
    [DispId(8)]  string LocalAddresses  { [param: In] set; get; }
    [DispId(9)]  string RemoteAddresses { [param: In] set; get; }
    [DispId(10)] string IcmpTypesAndCodes { [param: In] set; get; }
    [DispId(11)] object Direction     { [param: In] set; get; }
    [DispId(12)] object Interfaces    { [param: In] set; get; }
    [DispId(13)] string InterfaceTypes { [param: In] set; get; }
    [DispId(14)] bool   Enabled       { [param: In] set; get; }
    [DispId(15)] string Grouping      { [param: In] set; get; }
    [DispId(16)] int    Profiles      { [param: In] set; get; }
    [DispId(17)] bool   EdgeTraversal { [param: In] set; get; }
    [DispId(18)] object Action        { [param: In] set; get; }
}

[ComImport, Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
class NetFwRuleClass { }

// ─────────────────────────────────────────────────────────────────────────────

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
class Program
{
    #region Constants

    private const int    RefreshIntervalSeconds  = 3;
    private const int    MaxAlertLogEntries       = 50;
    private const string FirewallRulePrefix       = "TCP-Monitor-Block";
    private const string BlockedFile              = "blocked.txt";
    private const string IgnoredFile              = "ignored.txt";
    private const string CrashLogFile             = "crash.log";
    private const string EtwLogFile               = "etw_error.log";
    private const string GeoApiBase               = "http://ip-api.com/json/";
    private const double GeoThrottleSeconds       = 1.5;
    private const int    GeoMaxRetries            = 3;

    // NET_FW_ACTION_ and NET_FW_RULE_DIR_ enum values for COM interop
    private const int NET_FW_ACTION_BLOCK  = 0;
    private const int NET_FW_RULE_DIR_OUT  = 2;
    private const int NET_FW_IP_PROTOCOL_ANY = 256;

    #endregion

    #region Windows API — TCP Table

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, uint reserved = 0);

    private const int AF_INET                = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint TCP_STATE_ESTABLISHED  = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    #endregion

    #region FirewallManager — Native COM (no powershell.exe)

    /// <summary>
    /// Manages Windows Firewall rules via the native HNetCfg COM API.
    /// All calls are in-process and silent — no powershell.exe spawning.
    /// </summary>
    static class FirewallManager
    {
        // Lock so concurrent calls from async tasks don't corrupt COM state
        private static readonly object _fwLock = new();

        private static INetFwPolicy2? GetPolicy()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            return type is null ? null : (INetFwPolicy2?)Activator.CreateInstance(type);
        }

        /// <summary>Returns true if any rule with the given display name already exists.</summary>
        public static bool RuleExists(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return false;
                    foreach (INetFwRule r in policy.Rules)
                        if (r.Name.StartsWith(FirewallRulePrefix) && r.RemoteAddresses == ip)
                            return true;
                }
                catch (Exception ex) { LogCrash($"FirewallManager.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        /// <summary>Adds an outbound block rule for the given IP. No-ops if the rule already exists.</summary>
        public static bool AddBlockRule(string ip, string processName)
        {
            if (!IsValidIP(ip)) return false;
            if (RuleExists(ip)) return false; // Fix #3: deduplication

            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) { LogCrash("FirewallManager: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                    var rule = (INetFwRule)Activator.CreateInstance(ruleType)!;

                    rule.Name            = $"{FirewallRulePrefix}-{processName}-{ip}";
                    rule.Description     = $"Auto-blocked by TCP Monitor | process={processName}";
                    rule.Protocol        = NET_FW_IP_PROTOCOL_ANY;
                    rule.RemoteAddresses = ip;
                    rule.Direction       = NET_FW_RULE_DIR_OUT;
                    rule.Action          = NET_FW_ACTION_BLOCK;
                    rule.Enabled         = true;
                    rule.Profiles        = 0x7FFFFFFF; // All profiles

                    policy.Rules.Add(rule);
                    return true;
                }
                catch (Exception ex)
                {
                    LogCrash($"FirewallManager.AddBlockRule({ip}): {ex}");
                    return false;
                }
            }
        }

        /// <summary>Removes all TCP-Monitor block rules matching the given IP.</summary>
        public static void RemoveBlockRule(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return;

                    var toRemove = new List<string>();
                    foreach (INetFwRule r in policy.Rules)
                        if (r.Name.StartsWith(FirewallRulePrefix) && r.RemoteAddresses == ip)
                            toRemove.Add(r.Name);

                    foreach (var name in toRemove)
                        policy.Rules.Remove(name);
                }
                catch (Exception ex) { LogCrash($"FirewallManager.RemoveBlockRule({ip}): {ex}"); }
            }
        }
    }

    #endregion

    #region ETW Tracker

    public class EtwNetworkTracker : IDisposable
    {
        private static readonly string SessionName = KernelTraceEventParser.KernelSessionName;
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent     = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        private readonly object _lock = new();
        public bool IsRunning { get; private set; }

        public void Start()
        {
            try
            {
                // Force-stop any leftover session from a prior crash
                using (var existing = new TraceEventSession(SessionName))
                    existing.Stop(noThrow: true);

                Thread.Sleep(500); // Windows needs a moment to release the kernel handle

                _session = new TraceEventSession(SessionName) { StopOnDispose = true };
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                _session.Source.Kernel.TcpIpSend += data =>
                {
                    lock (_lock)
                        _bytesSent[data.ProcessID] = _bytesSent.GetValueOrDefault(data.ProcessID) + data.size;
                };
                _session.Source.Kernel.TcpIpRecv += data =>
                {
                    lock (_lock)
                        _bytesReceived[data.ProcessID] = _bytesReceived.GetValueOrDefault(data.ProcessID) + data.size;
                };

                Task.Run(() =>
                {
                    try   { IsRunning = true; _session.Source.Process(); }
                    catch (Exception ex) { File.AppendAllText(EtwLogFile, $"{DateTime.Now}: {ex}\n"); }
                    finally { IsRunning = false; }
                });
            }
            catch (Exception ex)
            {
                throw new Exception("ETW initialization failed. Are you running as Administrator?", ex);
            }
        }

        public (long Sent, long Received) GetStats(int pid)
        {
            lock (_lock)
                return (_bytesSent.GetValueOrDefault(pid), _bytesReceived.GetValueOrDefault(pid));
        }

        public void Dispose() => _session?.Dispose();
    }

    #endregion

    #region State

    static List<string>              _ignoredProcesses    = new();
    static Dictionary<string, string> _blockedIPs         = new();
    static HashSet<string>           _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
    static Dictionary<string, string> _domainCache        = new();
    static Dictionary<string, DateTime> _connectionStartTimes = new();
    static EtwNetworkTracker?        _etwTracker;
    static volatile bool             _running             = true;
    static bool                      _showExtraLists      = false;
    static readonly HttpClient       _http                = new();
    static readonly SemaphoreSlim    _geoSemaphore        = new(1, 1); // Fix #8: serial throttle
    static DateTime                  _lastGeoCall         = DateTime.MinValue;
    static readonly TimeSpan         _geoApiThrottle      = TimeSpan.FromSeconds(GeoThrottleSeconds);
    static Dictionary<string, string> _geoCache           = new();
    static readonly List<string>     _alertLog            = new();
    static readonly object           _alertLock           = new();
    static readonly HashSet<int>     _autoKilledPids      = new();

    // Cached connection list shared between DrawScreen and AutoEnforceBlockRules
    static List<TcpConnectionInfo>   _lastConnections     = new();
    static int                       _prevRowCount        = 0;

    #endregion

    #region Entry Point

    static void Main()
    {
        Console.Title = "TCP Monitor v4.0";

        // Fix #11/#12: Global error handling + cleanup on any exit path
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            LogCrash($"UNHANDLED: {e.ExceptionObject}");

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            _etwTracker?.Dispose();
            SaveAllData();
        };

        if (!IsAdministrator())
        {
            AnsiConsole.MarkupLine("[bold red]ERROR:[/] This program must run as Administrator for ETW tracing.");
            AnsiConsole.MarkupLine("[grey]Attempting to restart as Admin...[/]");
            Thread.Sleep(1500);
            RestartAsAdmin();
            return;
        }

        LoadAllData();
        RebuildBlockedProcessNames();
        _etwTracker = new EtwNetworkTracker();

        try { _etwTracker.Start(); }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            AnsiConsole.MarkupLine("[red]Press any key to exit...[/]");
            Console.ReadKey();
            return;
        }

        Console.CancelKeyPress += (_, e) => { e.Cancel = true; _running = false; };

        DateTime lastRefresh = DateTime.MinValue;

        while (_running)
        {
            // Fix #4: 3-second refresh instead of 2-second
            if ((DateTime.Now - lastRefresh).TotalSeconds >= RefreshIntervalSeconds)
            {
                // Fix #5: Fetch connections ONCE, share between enforce + draw
                _lastConnections = GetTcpConnections();
                AutoEnforceBlockRules(_lastConnections);
                DrawScreen(_lastConnections);
                lastRefresh = DateTime.Now;
            }

            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true);
                HandleKeyPress(key);
            }

            Thread.Sleep(50);
        }

        _etwTracker.Dispose();
        SaveAllData();
        AnsiConsole.MarkupLine("[yellow]Shutdown complete.[/]");
    }

    #endregion

    #region UIHelpers

    static void DrawScreen(List<TcpConnectionInfo> connections)
    {
        // Fix #14: Cursor-based redraw — position cursor at top without Console.Clear()
        Console.SetCursorPosition(0, 0);

        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title   = new TableTitle("[bold cyan]TCP-MONITOR LIVE FEED[/]");
        table.Caption = new TableTitle("[grey]Q Quit | K Kill | B Block | I Ignore | L Lists | H Help[/]");

        table.AddColumn("#");
        table.AddColumn("Process");
        table.AddColumn("PID");
        table.AddColumn("Remote Address");
        table.AddColumn("Geo / Org");
        table.AddColumn("Domain");
        table.AddColumn("Time");
        table.AddColumn(new TableColumn("Sent").RightAligned());
        table.AddColumn(new TableColumn("Recv").RightAligned());

        int overhead = _showExtraLists ? 30 : 10;
        int maxRows;
        try   { maxRows = Math.Max(1, Console.WindowHeight - overhead); }
        catch { maxRows = 20; }

        int displayCount = Math.Min(connections.Count, maxRows);
        for (int i = 0; i < displayCount; i++)
        {
            var c = connections[i];
            bool isBlocked = _blockedIPs.ContainsKey(c.RemoteIP) || _blockedProcessNames.Contains(c.ProcessName);
            string ipColor = isBlocked ? "red" : "white";

            table.AddRow(
                (i + 1).ToString(),
                $"[bold white]{Markup.Escape(c.ProcessName)}[/]",
                $"[grey]{c.PID}[/]",
                $"[{ipColor}]{Markup.Escape(c.RemoteIP)}[/]",
                $"[magenta]{Markup.Escape(c.Geo)}[/]",
                $"[blue]{Markup.Escape(c.Domain)}[/]",
                c.Duration,
                $"[green]{c.TotalSent}[/]",
                $"[yellow]{c.TotalReceived}[/]"
            );
        }

        AnsiConsole.Write(table);
        string etwStatus = _etwTracker!.IsRunning ? "[green]Active[/]" : "[red]Stopped[/]";
        AnsiConsole.MarkupLine(
            $"[grey]Connections: {connections.Count} | Blocked IPs: {_blockedIPs.Count} | ETW: {etwStatus}[/]");
        AnsiConsole.Write(new Rule());

        // Alert log
        lock (_alertLock)
        {
            if (_alertLog.Count > 0)
            {
                AnsiConsole.MarkupLine("[bold red on black] ⚠  AUTO-BLOCK ALERTS [/]");
                foreach (var alert in _alertLog.TakeLast(5))
                    AnsiConsole.MarkupLine(alert);
                AnsiConsole.Write(new Rule());
            }
        }

        if (_showExtraLists)
        {
            var grid = new Grid();
            grid.AddColumn(); grid.AddColumn(); grid.AddColumn();

            var bTable = new Table().Border(TableBorder.Rounded)
                .AddColumn("[red]Blocked IPs[/]").AddColumn("Process").AddColumn("Domain");
            foreach (var kvp in _blockedIPs.OrderBy(x => x.Key))
                bTable.AddRow(kvp.Key, $"[grey]{Markup.Escape(kvp.Value)}[/]",
                    $"[blue]{Markup.Escape(GetCachedDomain(kvp.Key))}[/]");
            if (_blockedIPs.Count == 0) bTable.AddRow("[grey]None[/]", "", "");

            var iTable = new Table().Border(TableBorder.Rounded).AddColumn("[yellow]Ignored Procs[/]");
            foreach (var proc in _ignoredProcesses.OrderBy(x => x)) iTable.AddRow(Markup.Escape(proc));
            if (_ignoredProcesses.Count == 0) iTable.AddRow("[grey]None[/]");

            var dTable = new Table().Border(TableBorder.Rounded)
                .AddColumn("[blue]Domain Cache (Last 15)[/]").AddColumn("Domain");
            foreach (var kvp in _domainCache.OrderBy(x => x.Key).TakeLast(15))
                dTable.AddRow(kvp.Key, Markup.Escape(kvp.Value));
            if (_domainCache.Count == 0) dTable.AddRow("[grey]None[/]", "");

            grid.AddRow(bTable, iTable, dTable);
            AnsiConsole.Write(grid);
        }

        // Fix #14: Clear only the lines that may have "ghost" content if the table shrank
        int currentRow = Console.CursorTop;
        if (_prevRowCount > displayCount)
        {
            int linesToClear = Math.Min(_prevRowCount - displayCount + 2, Console.WindowHeight - currentRow - 1);
            int width = Console.WindowWidth > 1 ? Console.WindowWidth - 1 : 0;
            for (int i = 0; i < linesToClear; i++)
                Console.WriteLine(new string(' ', width));
        }
        _prevRowCount = displayCount;
    }

    static void HandleKeyPress(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.Q: _running = false; break;
            case ConsoleKey.K: Console.Clear(); KillProcessInteractive(); break;
            case ConsoleKey.I: Console.Clear(); IgnoreProcessInteractive(); break;
            case ConsoleKey.B: Console.Clear(); ManageBlockedIPsInteractive(); break;
            case ConsoleKey.L: Console.Clear(); _showExtraLists = !_showExtraLists; break;
            case ConsoleKey.H:
            case ConsoleKey.F1:
                ShowHelp();
                break;
        }
    }

    static void ShowHelp()
    {
        AnsiConsole.Clear();

        string etwStatus  = _etwTracker?.IsRunning == true ? "[green]Running[/]" : "[red]Stopped[/]";
        string blockedCnt = _blockedIPs.Count.ToString();
        string ignoredCnt = _ignoredProcesses.Count.ToString();

        var panel = new Panel(
            $"[bold cyan]Keyboard Controls[/]\n" +
            $"  [cyan]Q[/]       Quit the monitor\n" +
            $"  [cyan]K[/]       Kill a process (interactive)\n" +
            $"  [cyan]B[/]       Block / unblock IPs (interactive)\n" +
            $"  [cyan]I[/]       Ignore / un-ignore processes (interactive)\n" +
            $"  [cyan]L[/]       Toggle blocked/ignored/domain lists\n" +
            $"  [cyan]H / F1[/]  Show this help screen\n\n" +
            $"[bold cyan]Status[/]\n" +
            $"  ETW Tracing : {etwStatus}\n" +
            $"  Blocked IPs : [red]{blockedCnt}[/]\n" +
            $"  Ignored     : [yellow]{ignoredCnt}[/]\n\n" +
            $"[bold cyan]Firewall Rules[/]\n" +
            $"  Rules are created natively via Windows Firewall COM API.\n" +
            $"  Display name format: [grey]{FirewallRulePrefix}-<process>-<ip>[/]\n" +
            $"  View in [italic]wf.msc → Outbound Rules[/].\n\n" +
            $"[bold cyan]Files[/]\n" +
            $"  [grey]{BlockedFile}[/]   — persisted block list (IP|process)\n" +
            $"  [grey]{IgnoredFile}[/]  — ignored process names (one per line)\n" +
            $"  [grey]{CrashLogFile}[/]  — error and exception log"
        ).Header("[bold]TCP Monitor Help[/]").Expand();

        AnsiConsole.Write(panel);
        AnsiConsole.MarkupLine("\nPress any key to return...");
        Console.ReadKey(true);
        Console.Clear();
    }

    #endregion

    #region ProcessControl

    static void KillProcessInteractive()
    {
        var conns = GetTcpConnections();
        if (conns.Count == 0) { AnsiConsole.MarkupLine("[grey]No active connections.[/]"); Thread.Sleep(800); return; }

        var choices = conns.Select(c => $"{c.PID}: {Markup.Escape(c.ProcessName)}").Distinct().ToList();
        choices.Add("Cancel");

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select process to [red]TERMINATE[/]:")
                .AddChoices(choices));

        if (selected == "Cancel") return;

        if (int.TryParse(selected.Split(':')[0], out int pid))
        {
            try   { Process.GetProcessById(pid).Kill(); AnsiConsole.MarkupLine("[green]Process terminated.[/]"); }
            catch (Exception ex) { AnsiConsole.MarkupLine($"[red]{Markup.Escape(ex.Message)}[/]"); }
            Thread.Sleep(1000);
        }
    }

    static void IgnoreProcessInteractive()
    {
        var conns    = GetTcpConnections(includeIgnored: true);
        var active   = conns.Select(c => c.ProcessName.ToLower()).Distinct().ToList();
        var allNames = active.Union(_ignoredProcesses).Distinct().OrderBy(x => x).ToList();

        if (allNames.Count == 0) return;

        var prompt = new MultiSelectionPrompt<string>()
            .Title("Select processes to [yellow]IGNORE[/] (Space=toggle, Enter=save):")
            .NotRequired().PageSize(15).AddChoices(allNames);

        foreach (var p in _ignoredProcesses)
            if (allNames.Contains(p)) prompt.Select(p);

        var selected = AnsiConsole.Prompt(prompt);
        _ignoredProcesses = selected.Select(x => x.ToLower()).ToList();
        SaveIgnoreList(); // Fix (ignored.txt): only write when user explicitly changes it
    }

    static void ManageBlockedIPsInteractive()
    {
        var conns     = GetTcpConnections();
        var activeIPs = conns.GroupBy(c => c.RemoteIP)
                             .ToDictionary(g => g.Key, g => g.First().ProcessName);
        var allIPs    = activeIPs.Keys.Union(_blockedIPs.Keys).Distinct().OrderBy(x => x).ToList();

        if (allIPs.Count == 0) { AnsiConsole.MarkupLine("[grey]No IPs available.[/]"); Thread.Sleep(800); return; }

        var choices = allIPs.Select(ip =>
        {
            string proc = activeIPs.TryGetValue(ip, out var ap) ? ap
                        : (_blockedIPs.TryGetValue(ip, out var bp) ? bp : "Unknown");
            return $"{ip} ({Markup.Escape(proc)})";
        }).ToList();

        var prompt = new MultiSelectionPrompt<string>()
            .Title("Select IPs to [red]BLOCK[/] (Space=toggle, Enter=save):")
            .NotRequired().PageSize(15).AddChoices(choices);

        foreach (var ip in _blockedIPs.Keys)
        {
            var choice = choices.FirstOrDefault(c => c.StartsWith(ip + " "));
            if (choice != null) prompt.Select(choice);
        }

        var selected    = AnsiConsole.Prompt(prompt);
        var selectedIPs = selected.Select(s => s.Split(' ')[0]).ToList();

        // Fix #16: Validate IPs before accepting them
        var invalidIPs = selectedIPs.Where(ip => !IsValidIP(ip)).ToList();
        if (invalidIPs.Count > 0)
        {
            AnsiConsole.MarkupLine($"[red]Skipping invalid IPs: {string.Join(", ", invalidIPs)}[/]");
            selectedIPs = selectedIPs.Except(invalidIPs).ToList();
            Thread.Sleep(1200);
        }

        var newlyBlocked   = selectedIPs.Except(_blockedIPs.Keys).ToList();
        var newlyUnblocked = _blockedIPs.Keys.Except(selectedIPs).ToList();

        var newDict = new Dictionary<string, string>();
        foreach (var s in selected)
        {
            string ip   = s.Split(' ')[0];
            if (!IsValidIP(ip)) continue;
            string proc = s.Substring(ip.Length + 2).TrimEnd(')');
            newDict[ip] = proc;
        }

        _blockedIPs = newDict;
        RebuildBlockedProcessNames();
        SaveBlockList();

        // Fix #1/#6/#7: Use FirewallManager instead of powershell.exe
        foreach (var ip in newlyBlocked)
        {
            string proc = _blockedIPs.TryGetValue(ip, out var p) ? p : "Unknown";
            bool added  = FirewallManager.AddBlockRule(ip, proc);
            if (!added)
                AnsiConsole.MarkupLine($"[yellow]Note: Firewall rule for {ip} may already exist or failed — check {CrashLogFile}[/]");
        }

        foreach (var ip in newlyUnblocked)
            FirewallManager.RemoveBlockRule(ip);

        AnsiConsole.MarkupLine($"[green]Saved. Blocked: {newlyBlocked.Count} added, {newlyUnblocked.Count} removed.[/]");
        Thread.Sleep(1000);
    }

    /// <summary>
    /// Fix #2: Corrected auto-kill logic (was inverted).
    /// Fix #3: Deduplication via RuleExists before adding firewall rules.
    /// Fix #1/#6/#7: Uses FirewallManager.AddBlockRule instead of powershell.exe.
    /// Accepts a pre-fetched connection list to avoid a redundant TCP table scan (Fix #5).
    /// </summary>
    static void AutoEnforceBlockRules(List<TcpConnectionInfo> conns)
    {
        if (_blockedProcessNames.Count == 0 && _blockedIPs.Count == 0) return;

        // ── Part 1: Kill any blocked process that is currently running ───────
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                if (!_blockedProcessNames.Contains(p.ProcessName)) continue;

                bool isNew; // Fix #2: Add() returns true when newly inserted
                lock (_alertLock) { isNew = _autoKilledPids.Add(p.Id); }

                if (isNew)
                {
                    try
                    {
                        p.Kill();
                        lock (_alertLock)
                        {
                            string t = DateTime.Now.ToString("HH:mm:ss");
                            _alertLog.Add(
                                $"[[{t}]] [red bold]AUTO-KILL:[/] [white]{Markup.Escape(p.ProcessName)}[/] " +
                                $"(PID {p.Id}) terminated");
                            if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
                        }
                    }
                    catch (Exception ex) { LogCrash($"AutoKill({p.Id}): {ex.Message}"); }
                }
            }
        }
        catch (Exception ex) { LogCrash($"AutoEnforceBlockRules (kill pass): {ex.Message}"); }

        // ── Part 2: Catch new IPs from blocked processes and firewall them ───
        foreach (var conn in conns)
        {
            if (!_blockedProcessNames.Contains(conn.ProcessName)) continue;
            if (!IsValidIP(conn.RemoteIP)) continue; // Fix #16

            bool isNewIp = !_blockedIPs.ContainsKey(conn.RemoteIP);
            if (!isNewIp) continue;

            _blockedIPs[conn.RemoteIP] = conn.ProcessName;
            RebuildBlockedProcessNames();
            SaveBlockList();

            // Fix #1/#6/#7: native COM — no powershell.exe
            bool added = FirewallManager.AddBlockRule(conn.RemoteIP, conn.ProcessName);

            lock (_alertLock)
            {
                string t = DateTime.Now.ToString("HH:mm:ss");
                string action = added ? "NEW IP BLOCKED" : "already blocked";
                _alertLog.Add(
                    $"[[{t}]] [red bold]AUTO-BLOCK:[/] [white]{Markup.Escape(conn.ProcessName)}[/] " +
                    $"(PID {conn.PID}) → [yellow]{conn.RemoteIP}[/] ({action})");
                if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
            }
        }
    }

    #endregion

    #region NetworkHelpers

    static List<TcpConnectionInfo> GetTcpConnections(bool includeIgnored = false)
    {
        var list       = new List<TcpConnectionInfo>();
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        IntPtr ptr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            if (GetExtendedTcpTable(ptr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return list;

            int    rowCount = Marshal.ReadInt32(ptr);
            IntPtr rowPtr   = ptr + 4;

            for (int i = 0; i < rowCount; i++)
            {
                try
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    if (row.dwState != TCP_STATE_ESTABLISHED) continue;

                    string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                    if (remoteIP.StartsWith("127.") || remoteIP == "0.0.0.0") continue;

                    int    pid   = (int)row.dwOwningPid;
                    string pName;
                    try
                    {
                        pName = Process.GetProcessById(pid).ProcessName;
                        if (!includeIgnored && _ignoredProcesses.Contains(pName.ToLower())) continue;
                    }
                    catch { continue; }

                    string key = $"{pid}-{remoteIP}";
                    if (!_connectionStartTimes.ContainsKey(key))
                        _connectionStartTimes[key] = DateTime.Now;

                    var stats = _etwTracker?.GetStats(pid) ?? (0, 0);

                    list.Add(new TcpConnectionInfo
                    {
                        ProcessName   = pName,
                        PID           = pid,
                        RemoteIP      = remoteIP,
                        Geo           = GetCachedGeo(remoteIP),
                        Domain        = GetCachedDomain(remoteIP),
                        Duration      = (DateTime.Now - _connectionStartTimes[key]).ToString(@"hh\:mm\:ss"),
                        TotalSent     = FormatBytes(stats.Sent),
                        TotalReceived = FormatBytes(stats.Received)
                    });
                }
                catch (Exception ex) { LogCrash($"GetTcpConnections row: {ex.Message}"); }
            }
        }
        finally { Marshal.FreeHGlobal(ptr); }

        return list.OrderByDescending(x => x.ProcessName).ToList();
    }

    static string FormatBytes(long bytes)
    {
        if (bytes < 1024)           return $"{bytes} B";
        if (bytes < 1024 * 1024)   return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    static string GetCachedDomain(string ip)
    {
        if (_domainCache.TryGetValue(ip, out var domain)) return domain;
        _domainCache[ip] = "...";
        Task.Run(() =>
        {
            try   { _domainCache[ip] = Dns.GetHostEntry(ip).HostName; }
            catch { _domainCache[ip] = "N/A"; }
        });
        return "...";
    }

    static string GetCachedGeo(string ip)
    {
        if (_geoCache.TryGetValue(ip, out var geo)) return geo;
        _geoCache[ip] = "...";
        Task.Run(async () => { _geoCache[ip] = await GeoIpLookupAsync(ip); });
        return "...";
    }

    /// <summary>
    /// Fix #8/#17: Uses SemaphoreSlim to serialize concurrent callers, plus
    /// exponential back-off retry on non-success HTTP responses.
    /// </summary>
    static async Task<string> GeoIpLookupAsync(string ip)
    {
        await _geoSemaphore.WaitAsync();
        try
        {
            // Throttle: ensure at least GeoThrottleSeconds between calls
            var wait = _geoApiThrottle - (DateTime.UtcNow - _lastGeoCall);
            if (wait > TimeSpan.Zero) await Task.Delay(wait);
            _lastGeoCall = DateTime.UtcNow;

            int delay = 500;
            for (int attempt = 0; attempt < GeoMaxRetries; attempt++)
            {
                try
                {
                    string url  = $"{GeoApiBase}{Uri.EscapeDataString(ip)}?fields=status,org,countryCode";
                    string json = await _http.GetStringAsync(url);

                    using var doc  = JsonDocument.Parse(json);
                    var root       = doc.RootElement;

                    if (!root.TryGetProperty("status", out var status) || status.GetString() != "success")
                    {
                        // Fix #17: back-off and retry on non-success
                        await Task.Delay(delay);
                        delay *= 2;
                        continue;
                    }

                    string org  = root.TryGetProperty("org",         out var o) ? o.GetString() ?? "" : "";
                    string code = root.TryGetProperty("countryCode", out var c) ? c.GetString() ?? "" : "";

                    if (org.Length > 3 && org[0] == 'A' && org[1] == 'S')
                    {
                        int space = org.IndexOf(' ');
                        if (space > 0) org = org[(space + 1)..];
                    }

                    return string.IsNullOrEmpty(code) ? org : $"{org} · {code}";
                }
                catch
                {
                    if (attempt == GeoMaxRetries - 1) return "N/A";
                    await Task.Delay(delay);
                    delay *= 2;
                }
            }
            return "N/A";
        }
        finally { _geoSemaphore.Release(); }
    }

    #endregion

    #region DataPersistence

    static void LoadAllData()
    {
        try
        {
            if (File.Exists(IgnoredFile))
                _ignoredProcesses = File.ReadAllLines(IgnoredFile)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim().ToLower())
                    .ToList();

            if (File.Exists(BlockedFile))
            {
                foreach (var line in File.ReadAllLines(BlockedFile))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Split('|');
                    string ip = parts[0].Trim();
                    if (IsValidIP(ip)) // Fix #16: validate on load
                        _blockedIPs[ip] = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                }
            }
        }
        catch (Exception ex) { LogCrash($"LoadAllData: {ex.Message}"); }
    }

    static void RebuildBlockedProcessNames()
    {
        _blockedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in _blockedIPs)
        {
            if (kvp.Value != "Unknown")
                _blockedProcessNames.Add(kvp.Value);
            if (!IPAddress.TryParse(kvp.Key, out _))
                _blockedProcessNames.Add(kvp.Key); // treat non-IP key as process name
        }
    }

    static void SaveAllData()
    {
        SaveIgnoreList();
        SaveBlockList();
    }

    // Fix (ignored.txt): Only called explicitly when the user changes the list via 'I'
    // or on shutdown — never in the main loop timer.
    static void SaveIgnoreList()
    {
        try   { File.WriteAllLines(IgnoredFile, _ignoredProcesses); }
        catch (Exception ex) { LogCrash($"SaveIgnoreList: {ex.Message}"); }
    }

    static void SaveBlockList()
    {
        try   { File.WriteAllLines(BlockedFile, _blockedIPs.Select(kvp => $"{kvp.Key}|{kvp.Value}")); }
        catch (Exception ex) { LogCrash($"SaveBlockList: {ex.Message}"); }
    }

    #endregion

    #region Utilities

    /// <summary>Fix #16: Validates that a string is a parseable IPv4/IPv6 address.</summary>
    static bool IsValidIP(string ip) =>
        !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

    static void LogCrash(string message) =>
        File.AppendAllText(CrashLogFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}\n");

    static bool IsAdministrator() =>
        new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent())
        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

    static void RestartAsAdmin()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName        = Process.GetCurrentProcess().MainModule!.FileName,
                UseShellExecute = true,
                Verb            = "runas",
                WorkingDirectory = Environment.CurrentDirectory
            });
        }
        catch (Exception ex) { LogCrash($"RestartAsAdmin: {ex.Message}"); }
    }

    #endregion
}

class TcpConnectionInfo
{
    public string ProcessName   { get; set; } = "";
    public int    PID           { get; set; }
    public string RemoteIP      { get; set; } = "";
    public string Geo           { get; set; } = "";
    public string Domain        { get; set; } = "";
    public string Duration      { get; set; } = "";
    public string TotalSent     { get; set; } = "";
    public string TotalReceived { get; set; } = "";
}