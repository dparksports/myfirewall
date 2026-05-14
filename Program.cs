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

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
class Program
{
    // --- Windows API for TCP Table ---
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

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

    // --- ETW Tracker (The Engine) ---
    public class EtwNetworkTracker : IDisposable
    {
        private static readonly string SessionName = KernelTraceEventParser.KernelSessionName;
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        private readonly object _lock = new();
        public bool IsRunning { get; private set; }

        public void Start()
        {
            try
            {
                // 1. Force stop any previous session left over
                using (var existing = new TraceEventSession(SessionName))
                {
                    existing.Stop(noThrow: true);
                }
                
                // 2. IMPORTANT: Windows needs a moment to release the kernel handle
                Thread.Sleep(500); 

                _session = new TraceEventSession(SessionName);
                _session.StopOnDispose = true;
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                _session.Source.Kernel.TcpIpSend += data =>
                {
                    lock (_lock) { _bytesSent[data.ProcessID] = _bytesSent.GetValueOrDefault(data.ProcessID) + data.size; }
                };

                _session.Source.Kernel.TcpIpRecv += data =>
                {
                    lock (_lock) { _bytesReceived[data.ProcessID] = _bytesReceived.GetValueOrDefault(data.ProcessID) + data.size; }
                };

                // Run processing in background
                Task.Run(() => {
                    try {
                        IsRunning = true;
                        _session.Source.Process();
                    }
                    catch (Exception ex) {
                        File.AppendAllText("etw_error.log", $"{DateTime.Now}: {ex}\n");
                    }
                    finally { IsRunning = false; }
                });
            }
            catch (Exception ex)
            {
                throw new Exception("ETW Initialization failed. Check if you are truly running as Admin.", ex);
            }
        }

        public (long Sent, long Received) GetStats(int pid)
        {
            lock (_lock)
            {
                return (_bytesSent.GetValueOrDefault(pid), _bytesReceived.GetValueOrDefault(pid));
            }
        }

        public void Dispose() => _session?.Dispose();
    }

    // --- State Variables ---
    static List<string> IgnoredProcesses = new();
    static Dictionary<string, string> BlockedIPs = new();
    static HashSet<string> BlockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
    static Dictionary<string, string> DomainCache = new();
    static Dictionary<string, DateTime> ConnectionStartTimes = new();
    static EtwNetworkTracker? EtwTracker;
    static bool Running = true;
    static bool ShowExtraLists = false;
    static readonly HttpClient _http = new HttpClient();
    static DateTime _lastGeoCall = DateTime.MinValue;
    static readonly TimeSpan GeoApiThrottle = TimeSpan.FromSeconds(1.5);
    static Dictionary<string, string> GeoCache = new();
    static readonly List<string> AlertLog = new();
    static readonly object AlertLock = new();
    static readonly HashSet<int> AutoKilledPids = new();

    static void Main()
    {
        Console.Title = "TCP Monitor v3.8";

        // Global Error Handling
        AppDomain.CurrentDomain.UnhandledException += (s, e) => {
            File.AppendAllText("crash.log", $"[{DateTime.Now}] CRITICAL: {e.ExceptionObject}\n");
        };

        if (!IsAdministrator())
        {
            AnsiConsole.MarkupLine("[bold red]ERROR:[/] You must run this as Administrator for ETW tracing.");
            AnsiConsole.MarkupLine("[grey]Attempting to restart as Admin...[/]");
            Thread.Sleep(1500);
            RestartAsAdmin();
            return;
        }

        LoadAllData();
        RebuildBlockedProcessNames();
        EtwTracker = new EtwNetworkTracker();
        
        try {
            EtwTracker.Start();
        }
        catch (Exception ex) {
            AnsiConsole.WriteException(ex);
            AnsiConsole.MarkupLine("[red]Press any key to exit...[/]");
            Console.ReadKey();
            return;
        }

        // Handle Ctrl+C
        Console.CancelKeyPress += (s, e) => { e.Cancel = true; Running = false; };

        DateTime lastRefresh = DateTime.MinValue;

        while (Running)
        {
            // Update UI every 2 seconds
            if ((DateTime.Now - lastRefresh).TotalSeconds >= 2)
            {
                AutoEnforceBlockRules();
                DrawScreen();
                lastRefresh = DateTime.Now;
            }

            // Non-blocking input check
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(true);
                HandleKeyPress(key);
            }

            Thread.Sleep(50); 
        }

        EtwTracker.Dispose();
        SaveAllData();
        AnsiConsole.MarkupLine("[yellow]Shutdown complete.[/]");
    }

    static void DrawScreen()
    {
        Console.SetCursorPosition(0, 0);
        var table = new Table().Border(TableBorder.Rounded).Expand();
        table.Title = new TableTitle("[bold cyan]TCP-MONITOR LIVE FEED[/]");
        table.Caption = new TableTitle("[grey]Press 'q' Quit | 'k' Kill | 'b' Block | 'i' Ignore | 'l' Lists[/]");

        table.AddColumn("#");
        table.AddColumn("Process");
        table.AddColumn("PID");
        table.AddColumn("Remote Address");
        table.AddColumn("Geo / Org");
        table.AddColumn("Domain");
        table.AddColumn("Time");
        table.AddColumn(new TableColumn("Sent").RightAligned());
        table.AddColumn(new TableColumn("Recv").RightAligned());

        var connections = GetTcpConnections();
        
        int maxRows = 20;
        try 
        { 
            int overhead = ShowExtraLists ? 30 : 10; // Extra lists take ~20 lines, base UI takes ~10
            maxRows = Math.Max(1, Console.WindowHeight - overhead); 
        } 
        catch { } // Fallback if WindowHeight is unavailable

        for (int i = 0; i < Math.Min(connections.Count, maxRows); i++)
        {
            var c = connections[i];
            table.AddRow(
                (i + 1).ToString(),
                $"[bold white]{c.ProcessName}[/]",
                $"[grey]{c.PID}[/]",
                c.RemoteIP,
                $"[magenta]{c.Geo}[/]",
                $"[blue]{c.Domain}[/]",
                c.Duration,
                $"[green]{c.TotalSent}[/]",
                $"[yellow]{c.TotalReceived}[/]"
            );
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"[grey]Total Connections: {connections.Count} | ETW Status: {(EtwTracker!.IsRunning ? "[green]Active[/]" : "[red]Stopped[/]")}[/]");
        AnsiConsole.Write(new Rule());

        // --- Alert Log ---
        lock (AlertLock)
        {
            if (AlertLog.Count > 0)
            {
                AnsiConsole.MarkupLine("[bold red on black] ⚠  AUTO-BLOCK ALERTS [/]");
                foreach (var alert in AlertLog.TakeLast(5))
                    AnsiConsole.MarkupLine(alert);
                AnsiConsole.Write(new Rule());
            }
        }
        
        if (ShowExtraLists)
        {
            var grid = new Grid();
            grid.AddColumn();
            grid.AddColumn();
            grid.AddColumn();
            
            var bTable = new Table().Border(TableBorder.Rounded).AddColumn("[red]Blocked IPs[/]").AddColumn("Process").AddColumn("Domain");
            foreach (var kvp in BlockedIPs.OrderBy(x => x.Key)) bTable.AddRow(kvp.Key, $"[grey]{kvp.Value}[/]", $"[blue]{GetCachedDomain(kvp.Key)}[/]");
            if (BlockedIPs.Count == 0) bTable.AddRow("[grey]None[/]", "", "");

            var iTable = new Table().Border(TableBorder.Rounded).AddColumn("[yellow]Ignored Procs[/]");
            foreach (var proc in IgnoredProcesses.OrderBy(x => x)) iTable.AddRow(proc);
            if (IgnoredProcesses.Count == 0) iTable.AddRow("[grey]None[/]");

            var dTable = new Table().Border(TableBorder.Rounded).AddColumn("[blue]Domain Cache (Last 15)[/]").AddColumn("Domain");
            foreach (var kvp in DomainCache.OrderBy(x => x.Key).TakeLast(15)) dTable.AddRow(kvp.Key, kvp.Value);
            if (DomainCache.Count == 0) dTable.AddRow("[grey]None[/]", "");

            grid.AddRow(bTable, iTable, dTable);
            AnsiConsole.Write(grid);
        }
        
        // Clear trailing lines to prevent ghosting when table shrinks
        for (int i = 0; i < 5; i++) Console.WriteLine(new string(' ', Console.WindowWidth - 1 > 0 ? Console.WindowWidth - 1 : 0));
    }

    static void HandleKeyPress(ConsoleKeyInfo key)
    {
        switch (key.Key)
        {
            case ConsoleKey.Q: Running = false; break;
            case ConsoleKey.K: Console.Clear(); KillProcessInteractive(); break;
            case ConsoleKey.I: Console.Clear(); IgnoreProcessInteractive(); break;
            case ConsoleKey.B: Console.Clear(); ManageBlockedIPsInteractive(); break;
            case ConsoleKey.L: Console.Clear(); ShowExtraLists = !ShowExtraLists; break;
            case ConsoleKey.H:
            case ConsoleKey.F1:
                ShowHelp();
                break;
        }
    }

    static void KillProcessInteractive()
    {
        var conns = GetTcpConnections();
        if (conns.Count == 0) return;

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select process to [red]TERMINATE[/]:")
                .AddChoices(conns.Select(c => $"{c.PID}: {c.ProcessName}").Distinct())
                .AddChoices("Cancel"));

        if (selected == "Cancel") return;

        int pid = int.Parse(selected.Split(':')[0]);
        try { Process.GetProcessById(pid).Kill(); } catch (Exception ex) { AnsiConsole.MarkupLine($"[red]{ex.Message}[/]"); Thread.Sleep(1000); }
    }

    static void IgnoreProcessInteractive()
    {
        var conns = GetTcpConnections(includeIgnored: true);
        var activeNames = conns.Select(c => c.ProcessName.ToLower()).Distinct().ToList();
        var allNames = activeNames.Union(IgnoredProcesses).Distinct().ToList();

        if (allNames.Count == 0) return;

        var prompt = new MultiSelectionPrompt<string>()
            .Title("Select processes to [red]IGNORE[/] (Space to toggle, Enter to save):")
            .NotRequired()
            .PageSize(15)
            .AddChoices(allNames);

        foreach (var ignored in IgnoredProcesses)
        {
            if (allNames.Contains(ignored)) prompt.Select(ignored);
        }

        var selected = AnsiConsole.Prompt(prompt);
        IgnoredProcesses = selected.Select(x => x.ToLower()).ToList();
        SaveIgnoreList();
    }

    static void ManageBlockedIPsInteractive()
    {
        var conns = GetTcpConnections();
        var activeIPs = conns.GroupBy(c => c.RemoteIP).ToDictionary(g => g.Key, g => g.First().ProcessName);
        var allIPs = activeIPs.Keys.Union(BlockedIPs.Keys).Distinct().ToList();

        if (allIPs.Count == 0) return;

        var choices = allIPs.Select(ip => {
            string proc = activeIPs.ContainsKey(ip) ? activeIPs[ip] : (BlockedIPs.ContainsKey(ip) ? BlockedIPs[ip] : "Unknown");
            return $"{ip} ({proc})";
        }).ToList();

        var prompt = new MultiSelectionPrompt<string>()
            .Title("Select IPs to [red]BLOCK[/] (Space to toggle, Enter to save):")
            .NotRequired()
            .PageSize(15)
            .AddChoices(choices);

        foreach (var ip in BlockedIPs.Keys)
        {
            var choice = choices.FirstOrDefault(c => c.StartsWith(ip + " "));
            if (choice != null) prompt.Select(choice);
        }

        var selected = AnsiConsole.Prompt(prompt);
        var selectedIPs = selected.Select(s => s.Split(' ')[0]).ToList();
        
        var newlyBlocked = selectedIPs.Except(BlockedIPs.Keys).ToList();
        var newlyUnblocked = BlockedIPs.Keys.Except(selectedIPs).ToList();

        var newDict = new Dictionary<string, string>();
        foreach(var s in selected)
        {
            string ip = s.Split(' ')[0];
            string proc = s.Substring(ip.Length + 2).TrimEnd(')');
            newDict[ip] = proc;
        }

        BlockedIPs = newDict;
        RebuildBlockedProcessNames();
        SaveBlockList();

        foreach (var ip in newlyBlocked)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"New-NetFirewallRule -DisplayName 'TCP-Monitor-Block-{BlockedIPs[ip]}-{ip}' -Direction Outbound -Action Block -RemoteAddress {ip}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit();
            } catch { }
        }

        foreach (var ip in newlyUnblocked)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Remove-NetFirewallRule -DisplayName '*TCP-Monitor-Block*-{ip}'\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                })?.WaitForExit();
            } catch { }
        }
    }

    static List<TcpConnectionInfo> GetTcpConnections(bool includeIgnored = false)
    {
        var list = new List<TcpConnectionInfo>();
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0) return list;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = tcpTablePtr + 4;

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                if (row.dwState != 5) continue; // Established only

                string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                if (remoteIP.StartsWith("127.") || remoteIP == "0.0.0.0") continue;

                int pid = (int)row.dwOwningPid;
                string pName = "Unknown";
                try { 
                    var p = Process.GetProcessById(pid);
                    pName = p.ProcessName;
                    if (!includeIgnored && IgnoredProcesses.Contains(pName.ToLower())) continue;
                } catch { continue; }

                string key = $"{pid}-{remoteIP}";
                if (!ConnectionStartTimes.ContainsKey(key)) ConnectionStartTimes[key] = DateTime.Now;

                var stats = EtwTracker?.GetStats(pid) ?? (0, 0);

                list.Add(new TcpConnectionInfo {
                    ProcessName = pName,
                    PID = pid,
                    RemoteIP = remoteIP,
                    Geo = GetCachedGeo(remoteIP),
                    Domain = GetCachedDomain(remoteIP),
                    Duration = (DateTime.Now - ConnectionStartTimes[key]).ToString(@"hh\:mm\:ss"),
                    TotalSent = FormatBytes(stats.Sent),
                    TotalReceived = FormatBytes(stats.Received)
                });
            }
        }
        finally { Marshal.FreeHGlobal(tcpTablePtr); }
        return list.OrderByDescending(x => x.ProcessName).ToList();
    }

    // --- Helpers ---
    static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    static string GetCachedDomain(string ip)
    {
        if (DomainCache.TryGetValue(ip, out var domain)) return domain;
        DomainCache[ip] = "...";
        Task.Run(() => {
            try {
                var d = Dns.GetHostEntry(ip).HostName;
                DomainCache[ip] = d;
            } catch { DomainCache[ip] = "N/A"; }
        });
        return "...";
    }

    static string GetCachedGeo(string ip)
    {
        if (GeoCache.TryGetValue(ip, out var geo)) return geo;
        GeoCache[ip] = "...";
        Task.Run(async () => {
            GeoCache[ip] = await GeoIpLookupAsync(ip);
        });
        return "...";
    }

    static async Task<string> GeoIpLookupAsync(string ip)
    {
        var elapsed = DateTime.UtcNow - _lastGeoCall;
        if (elapsed < GeoApiThrottle)
        {
            var wait = GeoApiThrottle - elapsed;
            await Task.Delay(wait);
        }
        _lastGeoCall = DateTime.UtcNow;

        try
        {
            string url = $"http://ip-api.com/json/{Uri.EscapeDataString(ip)}?fields=status,org,countryCode";
            string json = await _http.GetStringAsync(url);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!root.TryGetProperty("status", out var status) || status.GetString() != "success")
                return "N/A";

            string org  = root.TryGetProperty("org",         out var o) ? o.GetString() ?? "" : "";
            string code = root.TryGetProperty("countryCode", out var c) ? c.GetString() ?? "" : "";

            if (org.Length > 3 && org[0] == 'A' && org[1] == 'S')
            {
                int space = org.IndexOf(' ');
                if (space > 0) org = org[(space + 1)..];
            }

            return string.IsNullOrEmpty(code) ? org : $"{org} · {code}";
        }
        catch { return "N/A"; }
    }

    static bool IsAdministrator() => new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

    static void RestartAsAdmin() {
        try { 
            Process.Start(new ProcessStartInfo { 
                FileName = Process.GetCurrentProcess().MainModule!.FileName, 
                UseShellExecute = true, 
                Verb = "runas",
                WorkingDirectory = Environment.CurrentDirectory
            }); 
        } catch { }
    }

    static void ShowHelp() {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Panel("Keys:\n[cyan]Q[/] - Quit\n[cyan]K[/] - Kill Process\n[cyan]B[/] - Block IP\n[cyan]I[/] - Ignore Process").Header("Help"));
        AnsiConsole.MarkupLine("\nPress any key to return...");
        Console.ReadKey();
    }

    static void LoadAllData() {
        try {
            if (File.Exists("ignored.txt")) {
                IgnoredProcesses = File.ReadAllLines("ignored.txt")
                                       .Where(x => !string.IsNullOrWhiteSpace(x))
                                       .Select(x => x.Trim().ToLower())
                                       .ToList();
            }
            if (File.Exists("blocked.txt")) {
                foreach (var line in File.ReadAllLines("blocked.txt")) {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Split('|');
                    if (parts.Length == 2) BlockedIPs[parts[0].Trim()] = parts[1].Trim();
                    else BlockedIPs[line.Trim()] = "Unknown";
                }
            }
        } catch { }
    }

    static void RebuildBlockedProcessNames()
    {
        BlockedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in BlockedIPs)
        {
            if (kvp.Value != "Unknown") {
                BlockedProcessNames.Add(kvp.Value);
            }
            if (!IPAddress.TryParse(kvp.Key, out _)) {
                // If the key is not an IP address, it's a process name
                BlockedProcessNames.Add(kvp.Key);
            }
        }
    }

    /// <summary>
    /// Scans all live TCP connections. If a connection's process name is in the
    /// blocked list, it auto-adds a Windows Firewall outbound block rule for that
    /// IP, kills the process, and appends an entry to the on-screen alert log.
    /// </summary>
    static void AutoEnforceBlockRules()
    {
        if (BlockedProcessNames.Count == 0) return;

        // 1. Proactively terminate any running process that is in the block list
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                if (BlockedProcessNames.Contains(p.ProcessName))
                {
                    bool killed = false;
                    lock (AlertLock)
                    {
                        killed = !AutoKilledPids.Add(p.Id);
                    }

                    if (!killed)
                    {
                        try 
                        { 
                            p.Kill(); 
                            lock (AlertLock)
                            {
                                string alertTime = DateTime.Now.ToString("HH:mm:ss");
                                AlertLog.Add($"[[{alertTime}]] [red bold]AUTO-KILL:[/] [white]{p.ProcessName}[/] (PID {p.Id}) terminated proactively");
                                if (AlertLog.Count > 50) AlertLog.RemoveAt(0);
                            }
                        } 
                        catch { }
                    }
                }
            }
        }
        catch { }

        // 2. Scan live connections to catch new IPs and block them
        var conns = GetTcpConnections(includeIgnored: true);

        foreach (var conn in conns)
        {
            if (!BlockedProcessNames.Contains(conn.ProcessName)) continue;

            string alertTime = DateTime.Now.ToString("HH:mm:ss");
            bool newIp = !BlockedIPs.ContainsKey(conn.RemoteIP);

            // Add to in-memory block list and persist
            if (newIp)
            {
                BlockedIPs[conn.RemoteIP] = conn.ProcessName;
                RebuildBlockedProcessNames();
                SaveBlockList();

                // Add Windows Firewall rule for new IP
                try
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -Command \"New-NetFirewallRule -DisplayName 'TCP-Monitor-Block-{conn.ProcessName}-{conn.RemoteIP}' -Direction Outbound -Action Block -RemoteAddress {conn.RemoteIP}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    })?.WaitForExit();
                }
                catch { }

                // Log alert
                lock (AlertLock)
                {
                    AlertLog.Add($"[[{alertTime}]] [red bold]AUTO-BLOCK:[/] [white]{conn.ProcessName}[/] (PID {conn.PID}) tried to connect → [yellow]{conn.RemoteIP}[/] (NEW IP blocked)");
                    if (AlertLog.Count > 50) AlertLog.RemoveAt(0); // Keep log bounded
                }
            }
        }
    }

    static void SaveAllData() {
        File.WriteAllLines("ignored.txt", IgnoredProcesses);
        SaveBlockList();
    }
    static void SaveIgnoreList() => File.WriteAllLines("ignored.txt", IgnoredProcesses);
    static void SaveBlockList() => File.WriteAllLines("blocked.txt", BlockedIPs.Select(kvp => $"{kvp.Key}|{kvp.Value}"));
}

class TcpConnectionInfo
{
    public string ProcessName { get; set; } = "";
    public int PID { get; set; }
    public string RemoteIP { get; set; } = "";
    public string Geo { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Duration { get; set; } = "";
    public string TotalSent { get; set; } = "";
    public string TotalReceived { get; set; } = "";
}