#pragma warning disable SYSLIB0057
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
using DefaultPolicy = MyFirewall.Desktop.Services.DefaultPolicy;

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
partial class Program
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

    private static string BlockedFilePath => Path.Combine(ResolveBaseDir(), BlockedFile);
    private static string IgnoredFilePath => Path.Combine(ResolveBaseDir(), IgnoredFile);
    private static string CrashLogFilePath => Path.Combine(ResolveBaseDir(), CrashLogFile);
    private static string EtwLogFilePath => Path.Combine(ResolveBaseDir(), EtwLogFile);

    private static string ResolveBaseDir()
    {
        string? exeDir = Path.GetDirectoryName(Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName);
        if (!string.IsNullOrEmpty(exeDir))
        {
            string candidate = Path.GetFullPath(Path.Combine(exeDir, "..", "..", "..", ".."));
            if (Directory.Exists(candidate) && File.Exists(Path.Combine(candidate, "MyFirewall.csproj")))
                return candidate;
            return exeDir;
        }
        return AppDomain.CurrentDomain.BaseDirectory;
    }

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

        /// <summary>
        /// Adds a paired inbound + outbound block rule for the given IP.
        /// No-ops if the outbound rule already exists (deduplication guard).
        /// </summary>
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

                    // Outbound block
                    INetFwRule outRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    outRule.Name            = $"{FirewallRulePrefix}-{processName}-{ip}";
                    // Windows 11 24H2+/26H2 rejects '|' in rule Description with E_INVALIDARG on Add()
                    outRule.Description     = $"Auto-blocked by TCP Monitor - process={processName}";
                    outRule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    outRule.RemoteAddresses = ip;
                    outRule.Direction       = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    outRule.Action          = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    outRule.Enabled         = true;
                    outRule.Profiles        = 7; // All profiles
                    policy.Rules.Add(outRule);

                    // Inbound block — prevents reply packets from arriving and
                    // being counted by ETW even after the outbound rule is active.
                    INetFwRule inRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    inRule.Name            = $"{FirewallRulePrefix}-{processName}-{ip}-IN";
                    inRule.Description     = $"Auto-blocked (inbound) by TCP Monitor - process={processName}";
                    inRule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    inRule.RemoteAddresses = ip;
                    inRule.Direction       = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                    inRule.Action          = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    inRule.Enabled         = true;
                    inRule.Profiles        = 7;
                    policy.Rules.Add(inRule);

                    return true;
                }
                catch (Exception ex)
                {
                    LogCrash($"FirewallManager.AddBlockRule({ip}): {ex.Message}");
                    return false;
                }
            }
        }

        public static bool ApplyWebView2NetworkBlock(string path)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    try { policy.Rules.Remove("MyFirewall-Block-WebView2"); }    catch { }
                    try { policy.Rules.Remove("MyFirewall-Block-WebView2-IN"); } catch { }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;

                    // Outbound block
                    INetFwRule outRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    outRule.Name = "MyFirewall-Block-WebView2";
                    outRule.Description = "Proactively blocks msedgewebview2.exe outbound network connections.";
                    outRule.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    outRule.ApplicationName = path;
                    outRule.Direction = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    outRule.Action = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    outRule.Enabled = true;
                    outRule.Profiles = 7;
                    policy.Rules.Add(outRule);

                    // Inbound block — stops reply packets from arriving so ETW
                    // recv counters don't increment after the rule is in place.
                    INetFwRule inRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    inRule.Name = "MyFirewall-Block-WebView2-IN";
                    inRule.Description = "Proactively blocks msedgewebview2.exe inbound network connections.";
                    inRule.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    inRule.ApplicationName = path;
                    inRule.Direction = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                    inRule.Action = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    inRule.Enabled = true;
                    inRule.Profiles = 7;
                    policy.Rules.Add(inRule);

                    return true;
                }
                catch (Exception ex)
                {
                    LogCrash($"ApplyWebView2NetworkBlock failed: {ex.Message}");
                    return false;
                }
            }
        }

        public static void RemoveWebView2NetworkBlock()
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;
                    try { policy.Rules.Remove("MyFirewall-Block-WebView2"); }    catch { }
                    try { policy.Rules.Remove("MyFirewall-Block-WebView2-IN"); } catch { }
                }
                catch (Exception ex) { LogCrash($"RemoveWebView2NetworkBlock failed: {ex.Message}"); }
            }
        }

        /// <summary>
        /// Creates a paired inbound + outbound application-path-based block rule for any process.
        /// Application-path rules are evaluated by WFP before the first packet leaves the host,
        /// so traffic is blocked before any connection can be established — regardless of destination IP.
        /// </summary>
        public static bool AddAppBlockRule(string executablePath, string processName)
        {
            if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath)) return false;

            string outName = $"{FirewallRulePrefix}-{processName}-APP-OUT";
            string inName  = $"{FirewallRulePrefix}-{processName}-APP-IN";

            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    try { policy.Rules.Remove(outName); } catch { }
                    try { policy.Rules.Remove(inName);  } catch { }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;

                    INetFwRule outRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    outRule.Name            = outName;
                    outRule.Description     = $"App-level block (outbound) by TCP Monitor - {processName}";
                    
                    string? pfn = GetPackageFamilyName(executablePath);
                    if (pfn != null)
                    {
                        try { ((dynamic)outRule).LocalAppPackageId = pfn; } catch { }
                    }
                    else
                    {
                        outRule.ApplicationName = executablePath;
                    }
                    
                    outRule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    outRule.Direction       = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    outRule.Action          = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    outRule.Enabled         = true;
                    outRule.Profiles        = 7;
                    policy.Rules.Add(outRule);

                    INetFwRule inRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    inRule.Name            = inName;
                    inRule.Description     = $"App-level block (inbound) by TCP Monitor - {processName}";
                    
                    if (pfn != null)
                    {
                        try { ((dynamic)inRule).LocalAppPackageId = pfn; } catch { }
                    }
                    else
                    {
                        inRule.ApplicationName = executablePath;
                    }
                    
                    inRule.Protocol        = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    inRule.Direction       = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                    inRule.Action          = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    inRule.Enabled         = true;
                    inRule.Profiles        = 7;
                    policy.Rules.Add(inRule);

                    return true;
                }
                catch (Exception ex)
                {
                    LogCrash($"FirewallManager.AddAppBlockRule({processName}): {ex.Message}");
                    return false;
                }
            }
        }

        private static string? GetPackageFamilyName(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath)) return null;
            string pathLower = executablePath.ToLowerInvariant();
            if (!pathLower.Contains("\\windowsapps\\") && !pathLower.Contains("\\systemapps\\"))
                return null;

            string? folderName = null;
            var directory = Path.GetDirectoryName(executablePath);
            while (!string.IsNullOrEmpty(directory))
            {
                string dirName = Path.GetFileName(directory);
                string parent = Path.GetDirectoryName(directory) ?? "";
                if (parent.ToLowerInvariant().EndsWith("\\windowsapps") || parent.ToLowerInvariant().EndsWith("\\systemapps"))
                {
                    folderName = dirName;
                    break;
                }
                directory = parent;
            }

            if (string.IsNullOrEmpty(folderName)) return null;

            var parts = folderName.Split('_');
            if (parts.Length < 2) return folderName;

            return parts[0] + "_" + parts[parts.Length - 1];
        }

        /// <summary>
        /// True when an app-level block rule pair exists for the process name
        /// (used by the reconciliation sweep to detect drifted/deleted rules).
        /// </summary>
        public static bool AppBlockRuleExists(string processName)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return false;

                    try { if (policy.Rules.Item($"{FirewallRulePrefix}-{processName}-APP-OUT") != null) return true; } catch { }
                    try { if (policy.Rules.Item($"{FirewallRulePrefix}-{processName}-APP-IN") != null) return true; } catch { }
                }
                catch (Exception ex) { LogCrash($"FirewallManager.AppBlockRuleExists({processName}): {ex.Message}"); }
                return false;
            }
        }

        public static void RemoveAppBlockRule(string processName)
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;
                    try { policy.Rules.Remove($"{FirewallRulePrefix}-{processName}-APP-OUT"); } catch { }
                    try { policy.Rules.Remove($"{FirewallRulePrefix}-{processName}-APP-IN");  } catch { }
                }
                catch (Exception ex) { LogCrash($"FirewallManager.RemoveAppBlockRule({processName}): {ex.Message}"); }
            }
        }

        public static void RestoreHardcodedConfiguration()
        {
            lock (_fwLock)
            {
                try
                {
                    INetFwPolicy2? policy = GetPolicy();
                    if (policy is null) return;
                    
                    int count = 0;
                    foreach (INetFwRule rule in policy.Rules)
                    {
                        if (rule.Enabled)
                        {
                            try { rule.Enabled = false; count++; } catch { }
                        }
                    }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                    INetFwRule chromeRule = (INetFwRule)Activator.CreateInstance(ruleType)!;
                    
                    chromeRule.Name = "chrome.exe";
                    chromeRule.ApplicationName = @"C:\users\j3b650v2\appdata\local\google\chrome\application\chrome.exe";
                    chromeRule.Direction = NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_IN;
                    chromeRule.Action = NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    chromeRule.Profiles = 4; // NET_FW_PROFILE2_PUBLIC = 4
                    chromeRule.Enabled = true;
                    chromeRule.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;

                    policy.Rules.Add(chromeRule);
                }
                catch (Exception ex)
                {
                    LogCrash($"RestoreHardcodedConfiguration failed: {ex.Message}");
                    throw;
                }
            }
        }

        /// <summary>Removes all TCP-Monitor block rules (both directions) matching the given IP.</summary>
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
                            // Match both the outbound rule and the paired "-IN" inbound rule
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
        private static readonly string SessionName = "MyFirewallSession";
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent     = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        // PID → bare image name, fed by ETW ProcessStart; survives process exit so
        // connections whose owner died before a snapshot can still be attributed.
        private readonly Dictionary<int, string> _pidImage = new();
        private readonly object _lock = new();
        public bool IsRunning { get; private set; }

        private ProcessMonitoringStrategy _monitoringStrategy = ProcessMonitoringStrategy.ProcessStartEtw;
        public ProcessMonitoringStrategy MonitoringStrategy => _monitoringStrategy;
        public Action<string>? OnProactiveAlert { get; set; }
        private readonly HashSet<int> _proactiveEvaluatedPids = new();

        /// <summary>Set by the host: returns true when a process name is in the blocked set.</summary>
        public Func<string, bool>? IsBlockedProcess { get; set; }

        /// <summary>Raised in real time when a blocked process touches a remote endpoint
        /// (pid, processName, remoteIp, isUdp) — enforcement latency drops from one refresh
        /// interval to milliseconds, and send-and-die beacons are caught even though they
        /// never appear in a TCP-table snapshot.</summary>
        public Action<int, string, string, bool>? OnBlockedEndpoint { get; set; }

        public bool TryGetImageName(int pid, out string name)
        {
            lock (_lock) return _pidImage.TryGetValue(pid, out name!);
        }

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

                // Process keyword is now unconditional: blocked-process spawn handling and
                // PID→image attribution must work in both monitoring strategies.
                var keywords = KernelTraceEventParser.Keywords.NetworkTCPIP
                             | KernelTraceEventParser.Keywords.Process;
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

                // UDP was previously invisible to both the counters and enforcement.
                _session.Source.Kernel.UdpIpSend += data =>
                {
                    lock (_lock)
                        _bytesSent[data.ProcessID] = _bytesSent.GetValueOrDefault(data.ProcessID) + data.size;
                    HandleEndpointEvent(data.ProcessID, data.daddr?.ToString() ?? "", isUdp: true);
                };
                _session.Source.Kernel.UdpIpRecv += data =>
                {
                    lock (_lock)
                        _bytesReceived[data.ProcessID] = _bytesReceived.GetValueOrDefault(data.ProcessID) + data.size;
                };

                // Real-time TCP connect enforcement — a new destination for a blocked
                // process is firewall-blocked the moment the SYN leaves, not on the next scan.
                _session.Source.Kernel.TcpIpConnect += data =>
                {
                    HandleEndpointEvent(data.ProcessID, data.daddr?.ToString() ?? "", isUdp: false);
                };

                _session.Source.Kernel.ProcessStart += data =>
                {
                    if (data.ProcessID <= 0) return;

                    string imageName     = data.ImageFileName ?? string.Empty;
                    string bareImageName = Path.GetFileNameWithoutExtension(imageName);
                    bool   isWebView2    = imageName.Contains("msedgewebview2", StringComparison.OrdinalIgnoreCase);

                    lock (_lock) _pidImage[data.ProcessID] = bareImageName;

                    if (isWebView2 && _monitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw)
                    {
                        // WebView2: existing detailed handler — now also applies the block rule immediately
                        Task.Run(() => HandleWebView2Spawned(data.ProcessID));
                    }
                    else if (!isWebView2 && _blockedProcessNames.Contains(bareImageName))
                    {
                        // Any other blocked process: apply app-level firewall rule before first packet
                        Task.Run(() => HandleBlockedProcessSpawned(data.ProcessID, bareImageName));
                    }
                };

                _session.Source.Kernel.ProcessStop += data =>
                {
                    lock (_lock)
                    {
                        _pidImage.Remove(data.ProcessID);
                        _bytesSent.Remove(data.ProcessID);
                        _bytesReceived.Remove(data.ProcessID);
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

                // Apply firewall block the instant we have the executable path — ETW ProcessStart
                // fires before the process typically makes its first network call, so this rule
                // lands before any packet can leave the host.
                if (_blockedProcessNames.Contains("msedgewebview2") &&
                    !string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
                {
                    FirewallManager.ApplyWebView2NetworkBlock(executablePath);
                    ResetConnectionsForPid(pid);
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

        /// <summary>
        /// Called on ETW ProcessStart for any non-WebView2 process that is in _blockedProcessNames.
        /// Resolves the full executable path and immediately creates an application-path firewall rule
        /// (both inbound and outbound) so zero packets escape before the block is effective.
        /// </summary>
        private void HandleBlockedProcessSpawned(int pid, string processName)
        {
            lock (_lock)
            {
                if (_proactiveEvaluatedPids.Contains(pid)) return;
                _proactiveEvaluatedPids.Add(pid);
            }

            try
            {
                string executablePath = "N/A";
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, pid);
                    if (hProcess == IntPtr.Zero)
                        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

                    if (hProcess != IntPtr.Zero)
                    {
                        var sb = new System.Text.StringBuilder(1024);
                        int size = sb.Capacity;
                        if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                            executablePath = sb.ToString();
                    }
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                }

                if (!string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
                {
                    bool applied = FirewallManager.AddAppBlockRule(executablePath, processName);
                    if (applied)
                    {
                        ResetConnectionsForPid(pid);
                        OnProactiveAlert?.Invoke(
                            $"PROACTIVE BLOCK: [bold red]{Markup.Escape(processName)}[/] " +
                            $"spawned (PID {pid}) — app-level firewall rule applied instantly.\n" +
                            $"Path: [grey]{Markup.Escape(executablePath)}[/]");
                    }
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(EtwLogFilePath, $"HandleBlockedProcessSpawned error for PID {pid}: {ex}\n");
            }
        }

        /// <summary>
        /// ETW event path: attribute a connect/send event to a process image via the
        /// PID map and raise OnBlockedEndpoint when the process is in the blocked set.
        /// Runs on the ETW pump thread — handlers must be fast/non-blocking.
        /// </summary>
        private void HandleEndpointEvent(int pid, string remoteAddr, bool isUdp)
        {
            var handler = OnBlockedEndpoint;
            var predicate = IsBlockedProcess;
            if (handler == null || predicate == null) return;
            if (string.IsNullOrEmpty(remoteAddr)) return;
            if (remoteAddr.StartsWith("127.") || remoteAddr == "0.0.0.0" || remoteAddr == "::") return;

            string name;
            lock (_lock)
            {
                if (!_pidImage.TryGetValue(pid, out name!)) return;
            }
            if (string.IsNullOrEmpty(name) || !predicate(name)) return;

            handler(pid, name, remoteAddr, isUdp);
        }

        public (long Sent, long Received) GetStats(int pid)
        {
            lock (_lock)
                return (_bytesSent.GetValueOrDefault(pid), _bytesReceived.GetValueOrDefault(pid));
        }

        /// <summary>
        /// Clears the accumulated Sent/Recv counters for a PID so the UI
        /// shows zero after a block rule is applied rather than stale pre-block totals.
        /// </summary>
        public void ResetStats(int pid)
        {
            lock (_lock)
            {
                _bytesSent.Remove(pid);
                _bytesReceived.Remove(pid);
            }
        }

        public void Dispose() => Stop();
    }

    #endregion

    #region State

    static List<string>              _ignoredProcesses    = new();
    // Concurrent: mutated from the UI thread AND from ETW event enforcement tasks.
    static System.Collections.Concurrent.ConcurrentDictionary<string, BlockedIPMetadata> _blockedIPs  = new();
    static HashSet<string>           _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
    // name → executable path of every blocked process that has an app-level rule;
    // drives the reconciliation sweep and symmetric un-blocking.
    static Dictionary<string, string> _appRulePaths       = new(StringComparer.OrdinalIgnoreCase);
    static DateTime                  _lastSweep          = DateTime.MinValue;
    static System.Collections.Concurrent.ConcurrentDictionary<string, string> _domainCache  = new();
    static Dictionary<string, DateTime> _connectionStartTimes = new();
    static Dictionary<string, string> _socketHistory = new();
    static EtwNetworkTracker?        _etwTracker;
    static volatile bool             _running             = true;
    static readonly HttpClient       _http                = new();
    static readonly SemaphoreSlim    _geoSemaphore        = new(1, 1); // Fix #8: serial throttle
    static DateTime                  _lastGeoCall         = DateTime.MinValue;
    static readonly TimeSpan         _geoApiThrottle      = TimeSpan.FromSeconds(GeoThrottleSeconds);
    static System.Collections.Concurrent.ConcurrentDictionary<string, string> _geoCache     = new();
    static readonly List<string>     _alertLog            = new();
    static readonly object           _alertLock           = new();

    // Cached connection list shared between the TUI frame and AutoEnforceBlockRules
    static List<TcpConnectionInfo>   _lastConnections     = new();

    #endregion

    #region Entry Point

    static void Main(string[] args)
    {
        Console.Title = $"TCP Monitor v{typeof(Program).Assembly.GetName().Version?.ToString(3)}";
        MyFirewall.Services.TelemetryService.Instance.TrackEvent("cli_app_launch");

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
        ApplyProactiveProcessBlocks(); // Block processes already running at launch, before ETW starts
        ApplyStartupHardeningDefaults(); // Disable language sync / widgets / SearchHost / StartMenu & Shell hosts by default
        _etwTracker = new EtwNetworkTracker();
        _etwTracker.OnProactiveAlert = alertMsg =>
        {
            lock (_alertLock)
            {
                _alertLog.Add($"[{DateTime.Now:HH:mm:ss}] {alertMsg}");
                if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
            }
        };

        // Real-time enforcement: a blocked process touching a new destination is
        // firewall-blocked the moment the event arrives (milliseconds, not one
        // refresh interval), including UDP and send-and-die beacons.
        _etwTracker.IsBlockedProcess = name => _blockedProcessNames.Contains(name);
        _etwTracker.OnBlockedEndpoint = (pid, name, remoteIp, isUdp) =>
        {
            if (string.IsNullOrEmpty(remoteIp) || _blockedIPs.ContainsKey(remoteIp)) return;

            Task.Run(() =>
            {
                try
                {
                    if (!FirewallManager.AddBlockRule(remoteIp, name)) return;
                    _blockedIPs[remoteIp] = new BlockedIPMetadata { ProcessName = name, Timestamp = DateTime.Now };
                    RebuildBlockedProcessNames();
                    SaveBlockList();
                    ResetConnectionsToIp(remoteIp);
                    ResetConnectionsForPid(pid);
                    LogAlert($"EVENT-BLOCK{(isUdp ? " (UDP)" : "")}: [white]{Markup.Escape(name)}[/] → [yellow]{remoteIp}[/]");
                }
                catch (Exception ex) { LogCrash($"Event enforcement for {remoteIp}: {ex.Message}"); }
            });
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

        // TUI (Path A): one atomic Live frame — no repaint-in-place, no Console.Clear()
        // after startup. Keys are polled between refreshes; data refreshes on the timer.
        AnsiConsole.Live(new Rows())
            .AutoClear(true)
            .Overflow(VerticalOverflow.Crop)
            .Cropping(VerticalOverflowCropping.Bottom)
            .Start(ctx =>
            {
                while (_running)
                {
                    if ((DateTime.Now - lastRefresh).TotalSeconds >= RefreshIntervalSeconds)
                    {
                        // Fetch connections ONCE, shared between enforce + frame
                        _lastConnections = GetTcpConnections();
                        AutoEnforceBlockRules(_lastConnections);
                        lastRefresh = DateTime.Now;
                    }

                    // Reconciliation sweep (~30s): repair drifted/deleted app-level rules
                    if ((DateTime.Now - _lastSweep).TotalSeconds >= 30)
                    {
                        _lastSweep = DateTime.Now;
                        ReconcileBlockedProcessRules();
                    }

                    int keysPolled = 0;
                    while (_running && Console.KeyAvailable && keysPolled++ < 8)
                    {
                        HandleKeyPress(Console.ReadKey(true));
                    }

                    // Live diffing makes redundant refreshes cheap (identical frame = no output),
                    // and frequent refreshes keep the input caret and countdowns smooth.
                    ctx.UpdateTarget(BuildFrame(_lastConnections));
                    ctx.Refresh();

                    Thread.Sleep(40);
                }
            });

        _etwTracker.Dispose();
        SaveAllData();
        AnsiConsole.MarkupLine("[yellow]Shutdown complete.[/]");
    }

    #endregion


    #region ProcessControl


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
                ResetConnectionsForPid(conn.PID);     // Also close by PID in case IP mapping is stale

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

    /// <summary>
    /// Stops chasing IPs for processes we've already condemned: the moment a process
    /// name is in the blocked set, resolve its executable and apply an app-level
    /// ANY-protocol firewall rule so EVERY destination (new IPs, UDP included) is
    /// blocked by the firewall itself. Cached per name; retried on later rebuilds
    /// while the process isn't running (no path known yet).
    /// </summary>
    static void EnsureAppBlockRule(string processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return;
        if (processName is "Unknown" or "Idle") return;
        if (_appRulePaths.ContainsKey(processName)) return;

        string? path = null;
        try
        {
            foreach (var proc in Process.GetProcessesByName(processName))
            {
                try { path ??= proc.MainModule?.FileName; }
                catch { /* access denied for elevated/protected processes */ }
                finally { proc.Dispose(); }
                if (!string.IsNullOrEmpty(path)) break;
            }
        }
        catch { }

        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return; // not cached — retried on next rebuild

        if (FirewallManager.AddAppBlockRule(path, processName))
        {
            _appRulePaths[processName] = path;
            LogAlert($"APP-BLOCK: [white]{Markup.Escape(processName)}[/] — [red]app-level rule applied[/] (all destinations blocked)");
        }
    }

    /// <summary>
    /// Reconciliation sweep (~30s): re-asserts app-level rules for every blocked
    /// process, repairing rules deleted by other tools or policy refresh.
    /// </summary>
    static void ReconcileBlockedProcessRules()
    {
        foreach (var kvp in _appRulePaths.ToList())
        {
            if (FirewallManager.AppBlockRuleExists(kvp.Key)) continue;

            if (FirewallManager.AddAppBlockRule(kvp.Value, kvp.Key))
                LogAlert($"DRIFT: [yellow]{Markup.Escape(kvp.Key)}[/] app-level rule was missing — re-applied");
            else
                _appRulePaths.Remove(kvp.Key);
        }
    }

    /// <summary>
    /// Symmetric un-blocking: when an entry is removed, drop its app-level rule too,
    /// so un-blocking a process actually restores its network access.
    /// </summary>
    static void PruneAppRule(string removedKey, string attributedProcess)
    {
        if (IsValidIP(removedKey))
        {
            // IP entry: keep the app rule while any other entry still references the process.
            if (string.IsNullOrWhiteSpace(attributedProcess) || attributedProcess is "Unknown" or "Idle") return;
            bool stillReferenced =
                _blockedIPs.Values.Any(v => v.ProcessName.Equals(attributedProcess, StringComparison.OrdinalIgnoreCase)) ||
                _blockedProcessNames.Contains(attributedProcess);
            if (stillReferenced) return;
            RemoveAppRuleFor(attributedProcess);
        }
        else
        {
            RemoveAppRuleFor(removedKey); // explicit process entry removed
        }
    }

    static void RemoveAppRuleFor(string processName)
    {
        if (!_appRulePaths.Remove(processName)) return;
        FirewallManager.RemoveAppBlockRule(processName);
        LogAlert($"INFO: App-level rule removed for [white]{Markup.Escape(processName)}[/]");
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

    /// <summary>
    /// Tears down all active TCP connections owned by a specific PID.
    /// Complements ResetConnectionsToIp (destination-based) — use this immediately after
    /// applying an app-level or startup block so sockets that pre-date the rule are closed.
    /// </summary>
    static void ResetConnectionsForPid(int pid)
    {
        if (pid <= 0) return;

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (bufferSize <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(ptr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0) return;

            int    rowCount = Marshal.ReadInt32(ptr);
            IntPtr rowPtr   = ptr + 4;

            for (int i = 0; i < rowCount; i++)
            {
                try
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    if ((int)row.dwOwningPid != pid) continue;
                    if (row.dwState != TCP_STATE_ESTABLISHED && row.dwState != TCP_STATE_CLOSE_WAIT
                        && row.dwState != TCP_STATE_TIME_WAIT) continue;

                    MIB_TCPROW resetRow = new MIB_TCPROW
                    {
                        dwState      = MIB_TCP_STATE_DELETE_TCB,
                        dwLocalAddr  = row.dwLocalAddr,
                        dwLocalPort  = row.dwLocalPort,
                        dwRemoteAddr = row.dwRemoteAddr,
                        dwRemotePort = row.dwRemotePort
                    };

                    uint res = SetTcpEntry(ref resetRow);
                    if (res != 0)
                        LogCrash($"ResetConnectionsForPid: SetTcpEntry for PID {pid} failed (err {res})");
                }
                catch (Exception ex)
                {
                    LogCrash($"ResetConnectionsForPid row: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            LogCrash($"ResetConnectionsForPid: {ex.Message}");
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
                    catch
                    {
                        // Process already exited (e.g. a send-and-die beacon leaving only a
                        // TIME_WAIT socket): fall back to the ETW PID→image map so
                        // blocked-process attribution still works.
                        pName = (_etwTracker != null && _etwTracker.TryGetImageName(pid, out var img)) ? img : "Unknown";
                    }

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
                    string key = parts[0].Trim();
                    if (string.IsNullOrEmpty(key)) continue;

                    string app = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                    DateTime timestamp = DateTime.Now;
                    if (parts.Length >= 3 && DateTime.TryParse(parts[2].Trim(), out var dt))
                    {
                        timestamp = dt;
                    }

                    // Valid IPs are blocked by address; anything else is an explicit
                    // process-name entry (e.g. default policy process blocks such as
                    // MpCmdRun / MsMpEng / StartMenuExperienceHost).
                    _blockedIPs[key] = new BlockedIPMetadata { ProcessName = app, Timestamp = timestamp };
                }
            }

            SeedDefaultPolicy();
        }
        catch (Exception ex) { LogCrash($"LoadAllData: {ex.Message}"); }
    }

    /// <summary>
    /// Seeds the built-in default policy (adopted block list + default process blocks)
    /// into _blockedIPs. Existing user entries win, and entries recorded in
    /// defaults_removed.txt (explicit un-block opt-outs) are never re-added.
    /// </summary>
    static void SeedDefaultPolicy()
    {
        try
        {
            var removed = DefaultPolicy.LoadRemoved(ResolveBaseDir());

            foreach (var line in DefaultPolicy.DefaultBlockedIps)
            {
                var parts = line.Split('|');
                string key = parts[0].Trim();
                if (string.IsNullOrEmpty(key)) continue;
                if (removed.Contains(DefaultPolicy.BlockKey(key)) || _blockedIPs.ContainsKey(key)) continue;

                string app = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                DateTime timestamp = DateTime.Now;
                if (parts.Length >= 3 && DateTime.TryParse(parts[2].Trim(), out var dt)) timestamp = dt;
                _blockedIPs[key] = new BlockedIPMetadata { ProcessName = app, Timestamp = timestamp };
            }

            foreach (var (key, app) in DefaultPolicy.DefaultBlockedProcesses)
            {
                if (removed.Contains(DefaultPolicy.BlockKey(key)) || _blockedIPs.ContainsKey(key)) continue;
                _blockedIPs[key] = new BlockedIPMetadata { ProcessName = app, Timestamp = DateTime.Now };
            }
        }
        catch (Exception ex) { LogCrash($"SeedDefaultPolicy: {ex.Message}"); }
    }

    /// <summary>
    /// Applies the startup hardening defaults — language sync, Windows widgets,
    /// SearchHost box, SearchHost background & Bing search, StartMenuExperienceHost and
    /// ShellExperienceHost disabled, then the default kill list terminated — unless the
    /// user manually changed a toggle (opt-out recorded in the master switch).
    /// </summary>
    static void ApplyStartupHardeningDefaults()
    {
        try
        {
            if (!SystemSettingsManager.IsHardeningDefaultsEnabled()) return;

            SystemSettingsManager.SetLanguageSyncEnabled(false);
            SystemSettingsManager.SetWidgetsEnabled(false);
            SystemSettingsManager.SetSearchHostEnabled(false);
            SystemSettingsManager.SetSearchHostBackgroundAndBingDisabled(true);
            SystemSettingsManager.SetStartMenuExperienceHostEnabled(false);
            SystemSettingsManager.SetShellExperienceHostEnabled(false);

            var removed = DefaultPolicy.LoadRemoved(ResolveBaseDir());
            foreach (var name in DefaultPolicy.DefaultKillProcesses)
            {
                if (removed.Contains(DefaultPolicy.KillKey(name))) continue;
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { p.Kill(entireProcessTree: true); } catch { }
                }
            }

            AnsiConsole.MarkupLine("[grey]Hardening defaults applied: language sync, widgets, SearchHost box/background & Bing, StartMenuExperienceHost and ShellExperienceHost disabled.[/]");
        }
        catch (Exception ex) { LogCrash($"ApplyStartupHardeningDefaults: {ex.Message}"); }
    }

    static void RebuildBlockedProcessNames()
    {
        _blockedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in _blockedIPs)
        {
            if (!IPAddress.TryParse(kvp.Key, out _))
            {
                // Explicit process-name entry (non-IP key) → treat as a named process block
                _blockedProcessNames.Add(kvp.Key);
            }
            else
            {
                // IP entry: if the associated process has been blocked at ANY destination IP,
                // add it to the set so AutoEnforceBlockRules catches all future connections
                // from that process and firewall-blocks each new IP it tries to reach.
                // Note: this only creates new IP block rules — it never kills processes,
                // so it is safe for shared components like WebView2.
                if (!string.IsNullOrWhiteSpace(kvp.Value.ProcessName) &&
                    kvp.Value.ProcessName != "Unknown")
                {
                    _blockedProcessNames.Add(kvp.Value.ProcessName);
                }
            }
        }

        // Escalate to app-level rules: a blocked process gets an ANY-protocol
        // application rule so new destinations never need chasing.
        foreach (var name in _blockedProcessNames)
            EnsureAppBlockRule(name);
    }

    /// <summary>
    /// Runs once at startup, immediately after RebuildBlockedProcessNames.
    /// For every process name in the blocked set, finds running instances, resolves
    /// their executable paths, and applies app-level firewall rules + tears down
    /// existing TCP sockets — so processes already running at launch are blocked
    /// before the ETW session even starts.
    /// </summary>
    static void ApplyProactiveProcessBlocks()
    {
        foreach (string procName in _blockedProcessNames.ToList())
        {
            try
            {
                var processes = Process.GetProcessesByName(procName);
                foreach (var proc in processes)
                {
                    try
                    {
                        string executablePath = "N/A";
                        IntPtr hProcess = OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, proc.Id);
                        if (hProcess == IntPtr.Zero)
                            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);

                        if (hProcess != IntPtr.Zero)
                        {
                            try
                            {
                                var sb   = new System.Text.StringBuilder(1024);
                                int size = sb.Capacity;
                                if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                                    executablePath = sb.ToString();
                            }
                            finally { CloseHandle(hProcess); }
                        }

                        if (!string.IsNullOrEmpty(executablePath) && executablePath != "N/A" && File.Exists(executablePath))
                        {
                            bool applied = procName.Equals("msedgewebview2", StringComparison.OrdinalIgnoreCase)
                                ? FirewallManager.ApplyWebView2NetworkBlock(executablePath)
                                : FirewallManager.AddAppBlockRule(executablePath, procName);

                            if (applied)
                            {
                                ResetConnectionsForPid(proc.Id);
                                lock (_alertLock)
                                {
                                    _alertLog.Add($"[{DateTime.Now:HH:mm:ss}] [red bold]STARTUP BLOCK:[/] " +
                                        $"{Markup.Escape(procName)} (PID {proc.Id}) was already running — " +
                                        $"app-level firewall rule applied immediately.");
                                    if (_alertLog.Count > MaxAlertLogEntries) _alertLog.RemoveAt(0);
                                }
                            }
                        }
                    }
                    catch (Exception ex) { LogCrash($"ApplyProactiveProcessBlocks [{procName}]: {ex.Message}"); }
                    finally { proc.Dispose(); }
                }
            }
            catch (Exception ex) { LogCrash($"ApplyProactiveProcessBlocks: {ex.Message}"); }
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

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
static class SystemSettingsManager
{
    public static bool IsTelemetryEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\MyFirewall");
            if (key != null)
            {
                var val = key.GetValue("TelemetryEnabled");
                if (val is int intVal) return intVal == 1;
            }
            return true; // Default to true
        }
        catch { return true; }
    }

    public static void SetTelemetryEnabled(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\MyFirewall");
            key.SetValue("TelemetryEnabled", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { Program.LogCrash($"SetTelemetryEnabled: {ex.Message}"); }
    }

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

    /// <summary>
    /// Master switch for the startup hardening defaults (HKLM\SOFTWARE\Policies\MyFirewall).
    /// Absent value means enabled: defaults apply until the user manually changes a
    /// toggle, which records an opt-out so startup stops re-asserting.
    /// </summary>
    public static bool IsHardeningDefaultsEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\MyFirewall");
            if (key != null)
            {
                var val = key.GetValue("ApplyHardeningDefaults");
                if (val is int i && i == 0) return false;
            }
            return true;
        }
        catch { return true; }
    }

    public static void SetHardeningDefaultsEnabled(bool enable)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\MyFirewall");
            key.SetValue("ApplyHardeningDefaults", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { Program.LogCrash($"SetHardeningDefaultsEnabled: {ex.Message}"); }
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

    public static string? FindWebView2Path()
    {
        try
        {
            string baseDir = @"C:\Program Files (x86)\Microsoft\EdgeWebView\Application";
            if (System.IO.Directory.Exists(baseDir))
            {
                var exeFiles = System.IO.Directory.GetFiles(baseDir, "msedgewebview2.exe", System.IO.SearchOption.AllDirectories);
                if (exeFiles.Length > 0)
                {
                    var sorted = exeFiles.Select(f => new System.IO.FileInfo(f))
                                         .OrderByDescending(f => f.LastWriteTime)
                                         .ToList();
                    return sorted[0].FullName;
                }
            }
        }
        catch { }
        return null;
    }

    public static bool IsWebView2Blocked()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\MyFirewall");
            if (key != null)
            {
                var val = key.GetValue("BlockWebView2Network");
                if (val is int i && i == 1) return true;
            }
            return false;
        }
        catch { return false; }
    }

    public static void SetWebView2Blocked(bool block)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\MyFirewall");
            key.SetValue("BlockWebView2Network", block ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch (Exception ex) { Program.LogCrash($"SetWebView2Blocked: {ex.Message}"); }
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