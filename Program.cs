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
public enum NET_FW_IP_PROTOCOL { NET_FW_IP_PROTOCOL_TCP = 6, NET_FW_IP_PROTOCOL_UDP = 17, NET_FW_IP_PROTOCOL_ANY = 256 }
public enum NET_FW_RULE_DIRECTION { NET_FW_RULE_DIR_IN = 1, NET_FW_RULE_DIR_OUT = 2 }
public enum NET_FW_ACTION { NET_FW_ACTION_BLOCK = 0, NET_FW_ACTION_ALLOW = 1 }

[ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), CoClass(typeof(NetFwPolicy2Class)), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
interface INetFwPolicy2
{
    [DispId(1)]  int CurrentProfileTypes { get; }
    [DispId(2)]  bool FirewallEnabled { get; set; }
    [DispId(3)]  object ExcludedInterfaces { get; set; }
    [DispId(4)]  bool BlockAllInboundTraffic { get; set; }
    [DispId(5)]  bool NotificationsDisabled { get; set; }
    [DispId(6)]  bool UnicastResponsesToMulticastBroadcastDisabled { get; set; }
    [DispId(7)]  INetFwRules Rules { get; }
    [DispId(8)]  object ServiceRestriction { get; }
    [DispId(9)]  void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);
    [DispId(10)] bool IsRuleGroupEnabled(int profileTypesBitmask, string group);
    [DispId(11)] void RestoreLocalFirewallDefaults();
    [DispId(12)] NET_FW_ACTION DefaultInboundAction  { get; set; }
    [DispId(13)] NET_FW_ACTION DefaultOutboundAction { get; set; }
    [DispId(14)] bool IsRuleGroupCurrentlyEnabled(string group);
    [DispId(15)] object LocalPolicyModifyState { get; }
}

[ComImport, Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
class NetFwPolicy2Class { }

[ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
interface INetFwRules : System.Collections.IEnumerable
{
    [DispId(1)]  int Count { get; }
    [DispId(2)]  void Add(INetFwRule rule);
    [DispId(3)]  void Remove(string name);
    [DispId(4)]  INetFwRule Item(string name);
}

[ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2"), CoClass(typeof(NetFwRuleClass)), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
interface INetFwRule
{
    [DispId(1)]  string Name          { get; set; }
    [DispId(2)]  string Description   { get; set; }
    [DispId(3)]  string ApplicationName { get; set; }
    [DispId(4)]  string serviceName   { get; set; }
    [DispId(5)]  int    Protocol      { get; set; }
    [DispId(6)]  string LocalPorts    { get; set; }
    [DispId(7)]  string RemotePorts   { get; set; }
    [DispId(8)]  string LocalAddresses  { get; set; }
    [DispId(9)]  string RemoteAddresses { get; set; }
    [DispId(10)] string IcmpTypesAndCodes { get; set; }
    [DispId(11)] NET_FW_RULE_DIRECTION Direction { get; set; }
    [DispId(12)] object Interfaces    { get; set; }
    [DispId(13)] string InterfaceTypes { get; set; }
    [DispId(14)] bool   Enabled       { get; set; }
    [DispId(15)] string Grouping      { get; set; }
    [DispId(16)] int    Profiles      { get; set; }
    [DispId(17)] bool   EdgeTraversal { get; set; }
    [DispId(18)] NET_FW_ACTION Action { get; set; }
}

[ComImport, Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
class NetFwRuleClass { }

// ─────────────────────────────────────────────────────────────────────────────

public class BlockedIPMetadata
{
    public string ProcessName { get; set; } = "Unknown";
    public DateTime Timestamp { get; set; } = DateTime.Now;
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
class Program
{
    #region Constants

    private static int    RefreshIntervalSeconds  = 2;
    private const int    MaxAlertLogEntries       = 50;
    private const string FirewallRulePrefix       = "TCP-Monitor-Block";
    private const string BlockedFile              = "blocked.txt";
    private const string IgnoredFile              = "ignored.txt";
    private const string CrashLogFile             = "crash.log";
    private const string EtwLogFile               = "etw_error.log";
    private const string GeoApiBase               = "http://ip-api.com/json/";
    private const double GeoThrottleSeconds       = 1.5;
    private const int    GeoMaxRetries            = 3;

    private static string BlockedFilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, BlockedFile);
    private static string IgnoredFilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, IgnoredFile);
    private static string CrashLogFilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, CrashLogFile);
    private static string EtwLogFilePath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, EtwLogFile);

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
    private const uint TCP_STATE_CLOSE_WAIT   = 8;
    private const uint TCP_STATE_TIME_WAIT    = 11;

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

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MIB_TCPROW pTcprow);

    private const uint MIB_TCP_STATE_DELETE_TCB = 12;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, [Out] System.Text.StringBuilder lpExeName, ref int lpdwSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId; // Parent PID
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    #endregion

    #region FirewallManager — Native COM (no powershell.exe)

    public enum NET_FW_IP_PROTOCOL { NET_FW_IP_PROTOCOL_TCP = 6, NET_FW_IP_PROTOCOL_UDP = 17, NET_FW_IP_PROTOCOL_ANY = 256 }
    public enum NET_FW_RULE_DIRECTION { NET_FW_RULE_DIR_IN = 1, NET_FW_RULE_DIR_OUT = 2 }
    public enum NET_FW_ACTION { NET_FW_ACTION_BLOCK = 0, NET_FW_ACTION_ALLOW = 1 }

    [ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), CoClass(typeof(NetFwPolicy2Class))]
    interface INetFwPolicy2
    {
        int CurrentProfileTypes { get; }
        bool FirewallEnabled { get; set; }
        object ExcludedInterfaces { get; set; }
        bool BlockAllInboundTraffic { get; set; }
        bool NotificationsDisabled { get; set; }
        bool UnicastResponsesToMulticastBroadcastDisabled { get; set; }
        INetFwRules Rules { get; }
        object ServiceRestriction { get; }
        void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);
        bool IsRuleGroupEnabled(int profileTypesBitmask, string group);
        void RestoreLocalFirewallDefaults();
        NET_FW_ACTION DefaultInboundAction { get; set; }
        NET_FW_ACTION DefaultOutboundAction { get; set; }
        bool IsRuleGroupCurrentlyEnabled(string group);
        object LocalPolicyModifyState { get; }
    }

    [ComImport, Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
    class NetFwPolicy2Class { }

    [ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    interface INetFwRules : System.Collections.IEnumerable
    {
        int Count { get; }
        void Add(INetFwRule rule);
        void Remove(string name);
        INetFwRule Item(string name);
    }

    [ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2"), CoClass(typeof(NetFwRuleClass))]
    interface INetFwRule
    {
        string Name { get; set; }
        string Description { get; set; }
        string ApplicationName { get; set; }
        string serviceName { get; set; }
        int Protocol { get; set; }
        string LocalPorts { get; set; }
        string RemotePorts { get; set; }
        string LocalAddresses { get; set; }
        string RemoteAddresses { get; set; }
        string IcmpTypesAndCodes { get; set; }
        NET_FW_RULE_DIRECTION Direction { get; set; }
        object Interfaces { get; set; }
        string InterfaceTypes { get; set; }
        bool Enabled { get; set; }
        string Grouping { get; set; }
        int Profiles { get; set; }
        bool EdgeTraversal { get; set; }
        NET_FW_ACTION Action { get; set; }
    }

    [ComImport, Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
    class NetFwRuleClass { }

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
            return type is null ? null : (INetFwPolicy2)Activator.CreateInstance(type)!;
        }

        /// <summary>Returns true if a rule for this process and IP already exists.</summary>
        public static bool RuleExists(string ip, string processName)
        {
            string expectedName = $"{FirewallRulePrefix}-{processName}-{ip}";
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    foreach (INetFwRule r in policy.Rules)
                    {
                        try
                        {
                            if (r.Name == expectedName)
                                return true;
                        }
                        catch { /* skip rules we can't read */ }
                    }
                }
                catch (Exception ex) { LogCrash($"FirewallManager.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        /// <summary>Adds an outbound block rule for the given IP. No-ops if the rule already exists.</summary>
        public static bool AddBlockRule(string ip, string processName)
        {
            if (!IsValidIP(ip)) return false;
            if (RuleExists(ip, processName)) return true; // Fix #3: deduplication

            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) { LogCrash("FirewallManager: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                    
                    INetFwRule rule = (INetFwRule)Activator.CreateInstance(ruleType)!;

                    rule.Name            = $"{FirewallRulePrefix}-{processName}-{ip}";
                    rule.Description     = $"Auto-blocked by TCP Monitor | process={processName}";
                    rule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    rule.RemoteAddresses = ip;
                    rule.Direction       = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    rule.Action          = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    rule.Enabled         = true;
                    rule.Profiles        = 7; // All profiles

                    policy.Rules.Add(rule);
                    return true;
                }
                catch (Exception ex)
                {
                    LogCrash($"FirewallManager.AddBlockRule({ip}): {ex.Message}");
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
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;

                    var toRemove = new List<string>();
                    foreach (INetFwRule r in policy.Rules)
                    {
                        try
                        {
                            if (r.Name.StartsWith(FirewallRulePrefix) && r.RemoteAddresses == ip)
                                toRemove.Add(r.Name);
                        }
                        catch { }
                    }

                    foreach (var name in toRemove)
                        policy.Rules.Remove(name);
                }
                catch (Exception ex) { LogCrash($"FirewallManager.RemoveBlockRule({ip}): {ex.Message}"); }
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

        private ProcessMonitoringStrategy _monitoringStrategy = ProcessMonitoringStrategy.ProcessStartEtw;
        public ProcessMonitoringStrategy MonitoringStrategy => _monitoringStrategy;
        public Action<string>? OnProactiveAlert { get; set; }
        private readonly HashSet<int> _proactiveEvaluatedPids = new();

        public void SetMonitoringStrategy(ProcessMonitoringStrategy strategy)
        {
            if (_monitoringStrategy == strategy) return;
            _monitoringStrategy = strategy;

            if (IsRunning)
            {
                Stop();
                Start();
            }
        }

        public void Stop()
        {
            _session?.Dispose();
            _session = null;
        }

        public void Start()
        {
            try
            {
                // Force-stop any leftover session from a prior crash
                using (var existing = new TraceEventSession(SessionName))
                    existing.Stop(noThrow: true);

                Thread.Sleep(500); // Windows needs a moment to release the kernel handle

                lock (_lock)
                {
                    _proactiveEvaluatedPids.Clear();
                }

                _session = new TraceEventSession(SessionName) { StopOnDispose = true };
                
                var keywords = KernelTraceEventParser.Keywords.NetworkTCPIP;
                if (_monitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw)
                {
                    keywords |= KernelTraceEventParser.Keywords.Process;
                }
                _session.EnableKernelProvider(keywords);

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

                _session.Source.Kernel.ProcessStart += data =>
                {
                    if (_monitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw && data.ProcessID > 0)
                    {
                        string imageName = data.ImageFileName;
                        if (imageName.Contains("msedgewebview2", StringComparison.OrdinalIgnoreCase))
                        {
                            Task.Run(() => HandleWebView2Spawned(data.ProcessID));
                        }
                    }
                };

                Task.Run(() =>
                {
                    try   { IsRunning = true; _session.Source.Process(); }
                    catch (Exception ex) { File.AppendAllText(EtwLogFilePath, $"{DateTime.Now}: {ex}\n"); }
                    finally { IsRunning = false; }
                });
            }
            catch (Exception ex)
            {
                throw new Exception("ETW initialization failed. Are you running as Administrator?", ex);
            }
        }

        private void HandleWebView2Spawned(int pid)
        {
            lock (_lock)
            {
                if (_proactiveEvaluatedPids.Contains(pid)) return;
                _proactiveEvaluatedPids.Add(pid);
            }

            try
            {
                string parentProcessName = "Unknown";
                string executablePath = "N/A";
                string signature = "Unsigned / Unknown";

                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, pid);
                    if (hProcess == IntPtr.Zero)
                    {
                        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                    }

                    if (hProcess != IntPtr.Zero)
                    {
                        var sb = new System.Text.StringBuilder(1024);
                        int size = sb.Capacity;
                        if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                        {
                            executablePath = sb.ToString();
                        }

                        var pbi = new PROCESS_BASIC_INFORMATION();
                        int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                        if (status == 0)
                        {
                            int parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
                            if (parentPid > 0)
                            {
                                try
                                {
                                    using var parent = Process.GetProcessById(parentPid);
                                    parentProcessName = $"{parent.ProcessName} (PID {parentPid})";
                                }
                                catch
                                {
                                    parentProcessName = $"PID {parentPid} (Exited)";
                                }
                            }
                        }
                    }
                }
                catch
                {
                    try
                    {
                        using var process = Process.GetProcessById(pid);
                        executablePath = process.MainModule?.FileName ?? "N/A";
                    }
                    catch { }
                }
                finally
                {
                    if (hProcess != IntPtr.Zero)
                    {
                        CloseHandle(hProcess);
                    }
                }

                if (!string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
                {
                    try
                    {
                        using (var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(executablePath))
                        {
                            using (var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert))
                            {
                                string subject = cert2.Subject;
                                if (subject.Contains("CN="))
                                {
                                    int start = subject.IndexOf("CN=") + 3;
                                    int end = subject.IndexOf(',', start);
                                    if (end > start)
                                    {
                                        signature = "Signed by: " + subject.Substring(start, end - start);
                                    }
                                    else
                                    {
                                        signature = "Signed by: " + subject.Substring(start);
                                    }
                                }
                                else
                                {
                                    signature = "Signed: " + cert2.Subject;
                                }
                            }
                        }
                    }
                    catch
                    {
                        signature = "Unsigned";
                    }
                }

                string spawnReason = "General Rendering";
                string parentLower = parentProcessName.ToLower();
                if (parentLower.Contains("searchhost")) spawnReason = "Search UI rendering";
                else if (parentLower.Contains("widgets")) spawnReason = "Widgets content rendering";
                else if (parentLower.Contains("msedge")) spawnReason = "Edge browser sub-process";

                string color = signature.Contains("Signed") ? "green" : "red";
                OnProactiveAlert?.Invoke($"PROACTIVE: WebView2 Spawned PID {pid} by {parentProcessName} (Reason: {spawnReason}).\nPath: {executablePath}\nSignature: [{color}]{signature}[/]");
            }
            catch (Exception ex)
            {
                File.AppendAllText(EtwLogFilePath, $"Proactive error for PID {pid}: {ex}\n");
            }
        }

        public (long Sent, long Received) GetStats(int pid)
        {
            lock (_lock)
                return (_bytesSent.GetValueOrDefault(pid), _bytesReceived.GetValueOrDefault(pid));
        }

        public void Dispose() => Stop();
    }

    #endregion

    #region State

    static List<string>              _ignoredProcesses    = new();
    static Dictionary<string, BlockedIPMetadata> _blockedIPs  = new();
    static HashSet<string>           _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
    static System.Collections.Concurrent.ConcurrentDictionary<string, string> _domainCache  = new();
    static Dictionary<string, DateTime> _connectionStartTimes = new();
    static Dictionary<string, string> _socketHistory = new();
    static EtwNetworkTracker?        _etwTracker;
    static volatile bool             _running             = true;
    static bool                      _showExtraLists      = false;
    static readonly HttpClient       _http                = new();
    static readonly SemaphoreSlim    _geoSemaphore        = new(1, 1); // Fix #8: serial throttle
    static DateTime                  _lastGeoCall         = DateTime.MinValue;
    static readonly TimeSpan         _geoApiThrottle      = TimeSpan.FromSeconds(GeoThrottleSeconds);
    static System.Collections.Concurrent.ConcurrentDictionary<string, string> _geoCache     = new();
    static readonly List<string>     _alertLog            = new();
    static readonly object           _alertLock           = new();

    // Cached connection list shared between DrawScreen and AutoEnforceBlockRules
    static List<TcpConnectionInfo>   _lastConnections     = new();
    static int                       _prevRowCount        = 0;

    #endregion

    #region Entry Point

    static void Main(string[] args)
    {
        Console.Title = "TCP Monitor v5.0";

        // Parse arguments
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--refresh" && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int r) && r > 0)
                    RefreshIntervalSeconds = r;
            }
        }

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
        _etwTracker.OnProactiveAlert = alertMsg =>
        {
            lock (_alertLock)
            {
                _alertLog.Add($"[{DateTime.Now:HH:mm:ss}] {alertMsg}");
                if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
            }
        };

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
        table.Caption = new TableTitle("[grey]Q Quit | K Kill | B Block | I Ignore | P Details | S System Settings | T Toggle Strategy | L Lists | H Help[/]");

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

            string processDisplay = c.IsGhosted 
                ? $"[grey]{Markup.Escape(c.ProcessName)} (closed)[/]" 
                : $"[bold white]{Markup.Escape(c.ProcessName)}[/]";

            table.AddRow(
                (i + 1).ToString(),
                processDisplay,
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
                .AddColumn("[red]Blocked IPs[/]").AddColumn("Process").AddColumn("Domain").AddColumn("Blocked At");
            foreach (var kvp in _blockedIPs.OrderBy(x => x.Key))
                bTable.AddRow(kvp.Key, $"[grey]{Markup.Escape(kvp.Value.ProcessName)}[/]",
                    $"[blue]{Markup.Escape(GetCachedDomain(kvp.Key))}[/]",
                    $"[grey]{kvp.Value.Timestamp:yyyy-MM-dd HH:mm}[/]");
            if (_blockedIPs.Count == 0) bTable.AddRow("[grey]None[/]", "", "", "");

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
            case ConsoleKey.P: Console.Clear(); ShowProcessDetailsInteractive(); break;
            case ConsoleKey.S: Console.Clear(); ManageSystemSettingsInteractive(); break;
            case ConsoleKey.T:
                if (_etwTracker != null)
                {
                    var nextStrategy = _etwTracker.MonitoringStrategy == ProcessMonitoringStrategy.ConnectionDriven
                        ? ProcessMonitoringStrategy.ProcessStartEtw
                        : ProcessMonitoringStrategy.ConnectionDriven;
                    
                    _etwTracker.SetMonitoringStrategy(nextStrategy);
                    
                    lock (_alertLock)
                    {
                        _alertLog.Add($"[blue]INFO: Switched monitoring strategy to {nextStrategy}[/]");
                        if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
                    }
                    Console.Clear();
                }
                break;
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
        string strategy   = _etwTracker?.MonitoringStrategy.ToString() ?? "N/A";
        string blockedCnt = _blockedIPs.Count.ToString();
        string ignoredCnt = _ignoredProcesses.Count.ToString();

        var panel = new Panel(
            $"[bold cyan]Keyboard Controls[/]\n" +
            $"  [cyan]Q[/]       Quit the monitor\n" +
            $"  [cyan]K[/]       Kill a process (interactive)\n" +
            $"  [cyan]B[/]       Block / unblock IPs (interactive)\n" +
            $"  [cyan]I[/]       Ignore / un-ignore processes (interactive)\n" +
            $"  [cyan]P[/]       Process Intelligence / Details (interactive)\n" +
            $"  [cyan]S[/]       System Settings (Language sync, Widgets, Search, Hosts) (interactive)\n" +
            $"  [cyan]T[/]       Toggle Threat Intel Strategy (runtime)\n" +
            $"  [cyan]L[/]       Toggle blocked/ignored/domain lists\n" +
            $"  [cyan]H / F1[/]  Show this help screen\n\n" +
            $"[bold cyan]Status[/]\n" +
            $"  ETW Tracing     : {etwStatus}\n" +
            $"  Active Strategy : [cyan]{strategy}[/]\n" +
            $"  Blocked IPs     : [red]{blockedCnt}[/]\n" +
            $"  Ignored         : [yellow]{ignoredCnt}[/]\n\n" +
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

    static void ShowProcessDetailsInteractive()
    {
        var conns = GetTcpConnections();
        if (conns.Count == 0) { AnsiConsole.MarkupLine("[grey]No active connections.[/]"); Thread.Sleep(800); return; }

        var choices = conns.Select(c => $"{c.PID}: {Markup.Escape(c.ProcessName)}").Distinct().ToList();
        choices.Add("Cancel");

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select a process to view its [cyan]THREAT INTELLIGENCE[/]:")
                .AddChoices(choices));

        if (selected == "Cancel") return;

        if (int.TryParse(selected.Split(':')[0], out int pid))
        {
            AnsiConsole.Clear();
            AnsiConsole.MarkupLine($"[cyan]Resolving Threat Intelligence for PID {pid}...[/]");

            string parentProcessName = "Unknown";
            string executablePath = "N/A";
            string signature = "Unsigned / Unknown";
            string lastModified = "N/A";

            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                }

                if (hProcess != IntPtr.Zero)
                {
                    // 1. Path
                    var sb = new System.Text.StringBuilder(1024);
                    int size = sb.Capacity;
                    if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                    {
                        executablePath = sb.ToString();
                    }

                    // 2. Parent PID & Name
                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                    if (status == 0)
                    {
                        int parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
                        if (parentPid > 0)
                        {
                            try
                            {
                                using var parent = Process.GetProcessById(parentPid);
                                parentProcessName = $"{parent.ProcessName} (PID {parentPid})";
                            }
                            catch
                            {
                                parentProcessName = $"PID {parentPid} (Exited)";
                            }
                        }
                    }
                }
            }
            catch
            {
                try
                {
                    using var process = Process.GetProcessById(pid);
                    executablePath = process.MainModule?.FileName ?? "N/A";
                }
                catch { }
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }

            if (!string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
            {
                try
                {
                    var fileInfo = new FileInfo(executablePath);
                    lastModified = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");

                    using (var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(executablePath))
                    {
                        using (var cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert))
                        {
                            string subject = cert2.Subject;
                            if (subject.Contains("CN="))
                            {
                                int start = subject.IndexOf("CN=") + 3;
                                int end = subject.IndexOf(',', start);
                                if (end > start)
                                {
                                    signature = "Signed by: " + subject.Substring(start, end - start);
                                }
                                else
                                {
                                    signature = "Signed by: " + subject.Substring(start);
                                }
                            }
                            else
                            {
                                signature = "Signed: " + cert2.Subject;
                            }
                        }
                    }
                }
                catch
                {
                    signature = "Unsigned";
                }
            }

            var panel = new Panel(
                $"[bold cyan]APPLICATION[/]\n" +
                $"  Name: {Markup.Escape(selected.Split(':')[1].Trim())}\n" +
                $"  PID : {pid}\n\n" +
                $"[bold cyan]PARENT PROCESS[/]\n" +
                $"  {Markup.Escape(parentProcessName)}\n\n" +
                $"[bold cyan]DIGITAL SIGNATURE[/]\n" +
                $"  {Markup.Escape(signature)}\n\n" +
                $"[bold cyan]LOCATION (EXECUTABLE PATH)[/]\n" +
                $"  {Markup.Escape(executablePath)}\n\n" +
                $"[bold cyan]LAST MODIFIED[/]\n" +
                $"  {lastModified}"
            ).Header($"[bold]Threat Intelligence Report (PID {pid})[/]").Expand();

            AnsiConsole.Write(panel);
            AnsiConsole.MarkupLine("\nPress any key to return...");
            Console.ReadKey(true);
            Console.Clear();
        }
    }

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
            try
            {
                var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
                AnsiConsole.MarkupLine("[green]Process (and tree) terminated.[/]");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5)
            {
                AnsiConsole.MarkupLine("[red]Access Denied. System or protected process?[/]");
            }
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
                        : (_blockedIPs.TryGetValue(ip, out var bp) ? bp.ProcessName : "Unknown");
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

        var newDict = new Dictionary<string, BlockedIPMetadata>();
        foreach (var s in selected)
        {
            int openParen = s.IndexOf('(');
            int closeParen = s.LastIndexOf(')');
            if (openParen > 0 && closeParen > openParen)
            {
                string ip = s.Substring(0, openParen).Trim();
                if (!IsValidIP(ip)) continue;
                string proc = s.Substring(openParen + 1, closeParen - openParen - 1).Trim();
                DateTime timestamp = DateTime.Now;
                if (_blockedIPs.TryGetValue(ip, out var existing))
                    timestamp = existing.Timestamp;
                newDict[ip] = new BlockedIPMetadata { ProcessName = proc, Timestamp = timestamp };
            }
            else
            {
                string ip = s.Split(' ')[0];
                if (IsValidIP(ip))
                {
                    DateTime timestamp = DateTime.Now;
                    if (_blockedIPs.TryGetValue(ip, out var existing))
                        timestamp = existing.Timestamp;
                    newDict[ip] = new BlockedIPMetadata { ProcessName = "Unknown", Timestamp = timestamp };
                }
            }
        }

        _blockedIPs = newDict;
        RebuildBlockedProcessNames();
        SaveBlockList();

        // Fix #1/#6/#7: Use FirewallManager instead of powershell.exe
        foreach (var ip in newlyBlocked)
        {
            string proc = _blockedIPs.TryGetValue(ip, out var p) ? p.ProcessName : "Unknown";
            bool added  = FirewallManager.AddBlockRule(ip, proc);
            if (!added)
                AnsiConsole.MarkupLine($"[yellow]Note: Firewall rule for {ip} may already exist or failed — check {CrashLogFile}[/]");
            else
                ResetConnectionsToIp(ip); // Sever any existing active connections
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

        // ── Part 1: Catch new IPs from blocked processes and firewall them ───
        foreach (var conn in conns)
        {
            // We no longer auto-kill processes by name here to prevent system instability.
            // If a process is in _blockedProcessNames, we only block its new IPs.
            if (!_blockedProcessNames.Contains(conn.ProcessName)) continue;
            if (!IsValidIP(conn.RemoteIP)) continue; // Fix #16

            bool isNewIp = !_blockedIPs.ContainsKey(conn.RemoteIP);
            if (!isNewIp) continue;

            // Fix #1/#6/#7: native COM — no powershell.exe
            if (FirewallManager.AddBlockRule(conn.RemoteIP, conn.ProcessName))
            {
                _blockedIPs[conn.RemoteIP] = new BlockedIPMetadata { ProcessName = conn.ProcessName, Timestamp = DateTime.Now };
                RebuildBlockedProcessNames();
                SaveBlockList();
                ResetConnectionsToIp(conn.RemoteIP); // Sever any existing active connections

                lock (_alertLock)
                {
                    string t = DateTime.Now.ToString("HH:mm:ss");
                    _alertLog.Add(
                        $"[[{t}]] [red bold]AUTO-BLOCK:[/] [white]{Markup.Escape(conn.ProcessName)}[/] " +
                        $"(PID {conn.PID}) → [yellow]{conn.RemoteIP}[/] (NEW IP BLOCKED)");
                    if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
                }
            }
        }
    }

    static void ManageSystemSettingsInteractive()
    {
        while (true)
        {
            AnsiConsole.Clear();
            var syncEnabled = SystemSettingsManager.IsLanguageSyncEnabled() ? "[green]Enabled[/]" : "[red]Disabled[/]";
            var widgetsEnabled = SystemSettingsManager.IsWidgetsEnabled() ? "[green]Enabled[/]" : "[red]Disabled[/]";
            var searchEnabled = SystemSettingsManager.IsSearchHostEnabled() ? "[green]Enabled[/]" : "[red]Disabled[/]";
            var searchBgBingStatus = SystemSettingsManager.IsSearchHostBackgroundAndBingDisabled() ? "[red]Disabled[/]" : "[green]Enabled[/]";
            var startMenuEnabled = SystemSettingsManager.IsStartMenuExperienceHostEnabled() ? "[green]Enabled[/]" : "[red]Disabled[/]";
            var shellExpEnabled = SystemSettingsManager.IsShellExperienceHostEnabled() ? "[green]Enabled[/]" : "[red]Disabled[/]";

            var prompt = new SelectionPrompt<string>()
                .Title("[bold cyan]System Settings Management[/]\nSelect an option to toggle:")
                .AddChoices(
                    $"Toggle Language Sync (Current: {syncEnabled})",
                    $"Toggle Windows Widgets (Current: {widgetsEnabled})",
                    $"Toggle SearchHost Box (Current: {searchEnabled})",
                    $"Toggle SearchHost Background & Bing Search (Current: {searchBgBingStatus})",
                    $"Toggle StartMenuExperienceHost (Current: {startMenuEnabled})",
                    $"Toggle ShellExperienceHost (Current: {shellExpEnabled})",
                    "Stop SettingSyncHost Process",
                    "Stop Widgets Process",
                    "Stop SearchHost Process",
                    "Stop StartMenuExperienceHost Process",
                    "Stop ShellExperienceHost Process",
                    "Back to Monitor"
                );

            var selection = AnsiConsole.Prompt(prompt);

            if (selection == "Back to Monitor") break;

            if (selection.StartsWith("Toggle Language Sync"))
            {
                bool newState = !SystemSettingsManager.IsLanguageSyncEnabled();
                SystemSettingsManager.SetLanguageSyncEnabled(newState);
                AnsiConsole.MarkupLine($"Language Sync set to {(newState ? "[green]Enabled[/]" : "[red]Disabled[/]")}.");
                if (!newState) SystemSettingsManager.StopProcess("SettingSyncHost");
            }
            else if (selection.StartsWith("Toggle Windows Widgets"))
            {
                bool newState = !SystemSettingsManager.IsWidgetsEnabled();
                SystemSettingsManager.SetWidgetsEnabled(newState);
                AnsiConsole.MarkupLine($"Widgets set to {(newState ? "[green]Enabled[/]" : "[red]Disabled[/]")}.");
                if (!newState) SystemSettingsManager.StopProcess("Widgets");
            }
            else if (selection.StartsWith("Toggle SearchHost Box"))
            {
                bool newState = !SystemSettingsManager.IsSearchHostEnabled();
                SystemSettingsManager.SetSearchHostEnabled(newState);
                AnsiConsole.MarkupLine($"SearchHost Box set to {(newState ? "[green]Enabled[/]" : "[red]Disabled[/]")}.");
                if (!newState) SystemSettingsManager.StopProcess("SearchHost");
            }
            else if (selection.StartsWith("Toggle SearchHost Background & Bing Search"))
            {
                bool currentlyDisabled = SystemSettingsManager.IsSearchHostBackgroundAndBingDisabled();
                bool newStateDisable = !currentlyDisabled;
                SystemSettingsManager.SetSearchHostBackgroundAndBingDisabled(newStateDisable);
                AnsiConsole.MarkupLine($"SearchHost Background & Bing Search suggestions set to {(newStateDisable ? "[red]Disabled[/]" : "[green]Enabled[/]")}.");
                if (newStateDisable) SystemSettingsManager.StopProcess("SearchHost");
            }
            else if (selection.StartsWith("Toggle StartMenuExperienceHost"))
            {
                bool newState = !SystemSettingsManager.IsStartMenuExperienceHostEnabled();
                SystemSettingsManager.SetStartMenuExperienceHostEnabled(newState);
                AnsiConsole.MarkupLine($"StartMenuExperienceHost set to {(newState ? "[green]Enabled[/]" : "[red]Disabled[/]")}.");
                if (!newState) SystemSettingsManager.StopProcess("StartMenuExperienceHost");
            }
            else if (selection.StartsWith("Toggle ShellExperienceHost"))
            {
                bool newState = !SystemSettingsManager.IsShellExperienceHostEnabled();
                SystemSettingsManager.SetShellExperienceHostEnabled(newState);
                AnsiConsole.MarkupLine($"ShellExperienceHost set to {(newState ? "[green]Enabled[/]" : "[red]Disabled[/]")}.");
                if (!newState) SystemSettingsManager.StopProcess("ShellExperienceHost");
            }
            else if (selection.StartsWith("Stop SettingSyncHost Process"))
            {
                SystemSettingsManager.StopProcess("SettingSyncHost");
            }
            else if (selection.StartsWith("Stop Widgets Process"))
            {
                SystemSettingsManager.StopProcess("Widgets");
            }
            else if (selection.StartsWith("Stop SearchHost Process"))
            {
                SystemSettingsManager.StopProcess("SearchHost");
            }
            else if (selection.StartsWith("Stop StartMenuExperienceHost Process"))
            {
                SystemSettingsManager.StopProcess("StartMenuExperienceHost");
            }
            else if (selection.StartsWith("Stop ShellExperienceHost Process"))
            {
                SystemSettingsManager.StopProcess("ShellExperienceHost");
            }

            Thread.Sleep(1500);
        }
    }

    #endregion

    #region NetworkHelpers

    static void ResetConnectionsToIp(string destinationIp)
    {
        if (string.IsNullOrWhiteSpace(destinationIp)) return;

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(ptr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0) return;

            int rowCount = Marshal.ReadInt32(ptr);
            IntPtr rowPtr = ptr + 4;

            for (int i = 0; i < rowCount; i++)
            {
                try
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    if (row.dwState != TCP_STATE_ESTABLISHED && row.dwState != TCP_STATE_CLOSE_WAIT && row.dwState != TCP_STATE_TIME_WAIT) continue;

                    string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                    if (remoteIP == destinationIp)
                    {
                        MIB_TCPROW resetRow = new MIB_TCPROW
                        {
                            dwState = MIB_TCP_STATE_DELETE_TCB,
                            dwLocalAddr = row.dwLocalAddr,
                            dwLocalPort = row.dwLocalPort,
                            dwRemoteAddr = row.dwRemoteAddr,
                            dwRemotePort = row.dwRemotePort
                        };

                        uint res = SetTcpEntry(ref resetRow);
                        if (res != 0)
                        {
                            LogCrash($"SetTcpEntry failed for {remoteIP} with error code: {res}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogCrash($"ResetConnectionsToIp row: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            LogCrash($"ResetConnectionsToIp: {ex.Message}");
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

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

                    if (row.dwState != TCP_STATE_ESTABLISHED && row.dwState != TCP_STATE_CLOSE_WAIT && row.dwState != TCP_STATE_TIME_WAIT) continue;

                    string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                    if (remoteIP.StartsWith("127.") || remoteIP == "0.0.0.0") continue;

                    int    pid   = (int)row.dwOwningPid;
                    string pName = "Unknown";
                    bool isGhosted = false;
                    
                    int remotePort = IPAddress.NetworkToHostOrder((short)(row.dwRemotePort & 0xFFFF)) & 0xFFFF;
                    int localPort = IPAddress.NetworkToHostOrder((short)(row.dwLocalPort & 0xFFFF)) & 0xFFFF;
                    string socketKey = $"{remoteIP}:{remotePort}-{localPort}";

                    try
                    {
                        if (pid > 0)
                            pName = Process.GetProcessById(pid).ProcessName;
                        else
                            pName = "Idle";
                    }
                    catch { pName = "Unknown"; }

                    if ((pid == 0 || pName == "Idle" || pName == "Unknown") && _socketHistory.TryGetValue(socketKey, out string? originalName))
                    {
                        pName = originalName;
                        isGhosted = true;
                    }
                    else if (pid > 0 && pName != "Idle" && pName != "Unknown")
                    {
                        _socketHistory[socketKey] = pName;
                    }

                    if (!includeIgnored && _ignoredProcesses.Contains(pName.ToLower())) continue;

                    string key = $"{pid}-{remoteIP}:{remotePort}-{localPort}";
                    if (!_connectionStartTimes.ContainsKey(key))
                        _connectionStartTimes[key] = DateTime.Now;

                    var stats = _etwTracker?.GetStats(pid) ?? (0, 0);

                    list.Add(new TcpConnectionInfo
                    {
                        ProcessName   = pName,
                        IsGhosted     = isGhosted,
                        PID           = pid,
                        RemoteIP      = remoteIP,
                        RemotePort    = remotePort,
                        LocalPort     = localPort,
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

        var activeKeys = new HashSet<string>(list.Select(c => $"{c.PID}-{c.RemoteIP}:{c.RemotePort}-{c.LocalPort}"));
        var staleKeys = _connectionStartTimes.Keys.Where(k => !activeKeys.Contains(k)).ToList();
        foreach (var key in staleKeys) _connectionStartTimes.Remove(key);

        var activeSocketKeys = new HashSet<string>(list.Select(c => $"{c.RemoteIP}:{c.RemotePort}-{c.LocalPort}"));
        var staleSocketKeys = _socketHistory.Keys.Where(k => !activeSocketKeys.Contains(k)).ToList();
        foreach (var key in staleSocketKeys) _socketHistory.Remove(key);

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
            if (File.Exists(IgnoredFilePath))
                _ignoredProcesses = File.ReadAllLines(IgnoredFilePath)
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x.Trim().ToLower())
                    .ToList();

            if (File.Exists(BlockedFilePath))
            {
                foreach (var line in File.ReadAllLines(BlockedFilePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Split('|');
                    string ip = parts[0].Trim();
                    if (IsValidIP(ip)) // Fix #16: validate on load
                    {
                        string app = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                        DateTime timestamp = DateTime.Now;
                        if (parts.Length >= 3 && DateTime.TryParse(parts[2].Trim(), out var dt))
                        {
                            timestamp = dt;
                        }
                        _blockedIPs[ip] = new BlockedIPMetadata { ProcessName = app, Timestamp = timestamp };
                    }
                }
            }
        }
        catch (Exception ex) { LogCrash($"LoadAllData: {ex.Message}"); }
    }

    static void RebuildBlockedProcessNames()
    {
        _blockedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Note: We no longer auto-populate process names from _blockedIPs to avoid
        // aggressive kill-loops for shared components like WebView2.
        // Process name blocking is now an explicit, separate action if added in the future.
        foreach (var kvp in _blockedIPs)
        {
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
        try   { File.WriteAllLines(IgnoredFilePath, _ignoredProcesses); }
        catch (Exception ex) { LogCrash($"SaveIgnoreList: {ex.Message}"); }
    }

    static void SaveBlockList()
    {
        try   { File.WriteAllLines(BlockedFilePath, _blockedIPs.Select(kvp => $"{kvp.Key}|{kvp.Value.ProcessName}|{kvp.Value.Timestamp:O}")); }
        catch (Exception ex) { LogCrash($"SaveBlockList: {ex.Message}"); }
    }

    #endregion

    #region Utilities

    /// <summary>Fix #16: Validates that a string is a parseable IPv4/IPv6 address.</summary>
    static bool IsValidIP(string ip) =>
        !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip, out _);

    internal static void LogCrash(string message) =>
        File.AppendAllText(CrashLogFilePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}\n");

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

enum ProcessMonitoringStrategy
{
    ConnectionDriven,
    ProcessStartEtw
}

class TcpConnectionInfo
{
    public string ProcessName   { get; set; } = "";
    public int    PID           { get; set; }
    public string RemoteIP      { get; set; } = "";
    public string Geo           { get; set; } = "";
    public string Domain        { get; set; } = "";
    public int    RemotePort    { get; set; }
    public int    LocalPort     { get; set; }
    public string Duration      { get; set; } = "";
    public string TotalSent     { get; set; } = "";
    public string TotalReceived { get; set; } = "";
    public bool   IsGhosted     { get; set; }
}

static class SystemSettingsManager
{
    public static bool IsLanguageSyncEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\SettingSync");
            if (key != null)
            {
                var val = key.GetValue("DisableLanguageSettingSync");
                if (val is int i && i == 1) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static void SetLanguageSyncEnabled(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\SettingSync");
            key.SetValue("DisableLanguageSettingSync", enable ? 0 : 1, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { Program.LogCrash($"SetLanguageSyncEnabled: {ex.Message}"); }
    }

    public static bool IsWidgetsEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Dsh");
            if (key != null)
            {
                var val = key.GetValue("AllowNewsAndInterests");
                if (val is int i && i == 0) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static void SetWidgetsEnabled(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Dsh");
            key.SetValue("AllowNewsAndInterests", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
            
            if (!enable)
            {
                // Run powershell to remove web experience package
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-Command \"Get-AppxPackage *WebExperience* | Remove-AppxPackage\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(psi);
            }
        }
        catch (Exception ex) { Program.LogCrash($"SetWidgetsEnabled: {ex.Message}"); }
    }

    public static bool IsSearchHostEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
            if (key != null)
            {
                var val = key.GetValue("SearchboxTaskbarMode");
                if (val is int i && i == 0) return false;
            }
            return true; // Default is true (enabled)
        }
        catch { return true; }
    }

    public static void SetSearchHostEnabled(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
            key.SetValue("SearchboxTaskbarMode", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { Program.LogCrash($"SetSearchHostEnabled: {ex.Message}"); }
    }

    public static bool IsSearchHostBackgroundAndBingDisabled()
    {
        try
        {
            using var bgKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.Client.CBS_cw5n1h2txyew");
            bool bgDisabled = false;
            if (bgKey != null)
            {
                var d = bgKey.GetValue("Disabled");
                var dbu = bgKey.GetValue("DisabledByUser");
                if (d is int di && di == 1 && dbu is int dbui && dbui == 1)
                {
                    bgDisabled = true;
                }
            }

            using var expKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\Explorer");
            bool bingDisabled = false;
            if (expKey != null)
            {
                var val = expKey.GetValue("DisableSearchBoxSuggestions");
                if (val is int i && i == 1)
                {
                    bingDisabled = true;
                }
            }

            return bgDisabled && bingDisabled;
        }
        catch { return false; }
    }

    public static void SetSearchHostBackgroundAndBingDisabled(bool disable)
    {
        try
        {
            using var bgKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.Client.CBS_cw5n1h2txyew");
            bgKey.SetValue("Disabled", disable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
            bgKey.SetValue("DisabledByUser", disable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);

            using var expKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\Explorer");
            if (disable)
            {
                expKey.SetValue("DisableSearchBoxSuggestions", 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            else
            {
                try { expKey.DeleteValue("DisableSearchBoxSuggestions", false); } catch {}
            }

            using var searchKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Search");
            if (disable)
            {
                searchKey.SetValue("BingSearchEnabled", 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            else
            {
                try { searchKey.DeleteValue("BingSearchEnabled", false); } catch {}
            }
        }
        catch (Exception ex) { Program.LogCrash($"SetSearchHostBackgroundAndBingDisabled: {ex.Message}"); }
    }

    public static bool IsStartMenuExperienceHostEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe");
            if (key != null)
            {
                var val = key.GetValue("Debugger");
                if (val != null) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static void SetStartMenuExperienceHostEnabled(bool enable)
    {
        try
        {
            if (enable)
            {
                using var parentKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", writable: true);
                if (parentKey != null)
                {
                    parentKey.DeleteSubKeyTree("StartMenuExperienceHost.exe", throwOnMissingSubKey: false);
                }
            }
            else
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe");
                key.SetValue("Debugger", "systray.exe", Microsoft.Win32.RegistryValueKind.String);
            }
        }
        catch (Exception ex) { Program.LogCrash($"SetStartMenuExperienceHostEnabled: {ex.Message}"); }
    }

    public static bool IsShellExperienceHostEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe");
            if (key != null)
            {
                var val = key.GetValue("Debugger");
                if (val != null) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static void SetShellExperienceHostEnabled(bool enable)
    {
        try
        {
            if (enable)
            {
                using var parentKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", writable: true);
                if (parentKey != null)
                {
                    parentKey.DeleteSubKeyTree("ShellExperienceHost.exe", throwOnMissingSubKey: false);
                }
            }
            else
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe");
                key.SetValue("Debugger", "systray.exe", Microsoft.Win32.RegistryValueKind.String);
            }
        }
        catch (Exception ex) { Program.LogCrash($"SetShellExperienceHostEnabled: {ex.Message}"); }
    }

    public static void StopProcess(string processName)
    {
        try
        {
            var processes = Process.GetProcessesByName(processName);
            foreach (var p in processes)
            {
                p.Kill(entireProcessTree: true);
            }
            if (processes.Length > 0)
            {
                AnsiConsole.MarkupLine($"[yellow]Stopped {processName} process.[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[grey]{processName} is not running.[/]");
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to stop {processName}: {ex.Message}[/]");
        }
    }
}