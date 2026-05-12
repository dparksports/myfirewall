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
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
class Program
{
    // --- Constants and Native Methods ---
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

    // --- ETW Tracker Logic ---
    public class EtwNetworkTracker : IDisposable
    {
        private const string SessionName = "TcpMonitorEtwSession_Persistent";
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        private readonly object _lock = new();

        public void Start()
        {
            // IMPORTANT: Clear any existing session with this name that might be hanging from a crash
            try
            {
                using (var existing = new TraceEventSession(SessionName))
                {
                    existing.Stop(noThrow: true);
                }
            }
            catch { /* Ignore cleanup errors */ }

            _session = new TraceEventSession(SessionName);
            _session.StopOnDispose = true; // Ensures the session closes if the app is killed
            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

            _session.Source.Kernel.TcpIpSend += data =>
            {
                int pid = data.ProcessID;
                long size = data.size;
                lock (_lock) { if (!_bytesSent.ContainsKey(pid)) _bytesSent[pid] = 0; _bytesSent[pid] += size; }
            };

            _session.Source.Kernel.TcpIpRecv += data =>
            {
                int pid = data.ProcessID;
                long size = data.size;
                lock (_lock) { if (!_bytesReceived.ContainsKey(pid)) _bytesReceived[pid] = 0; _bytesReceived[pid] += size; }
            };

            Task.Run(() => _session.Source.Process());
        }

        public (long Sent, long Received) GetStats(int pid)
        {
            lock (_lock)
            {
                long sent = _bytesSent.TryGetValue(pid, out var s) ? s : 0;
                long received = _bytesReceived.TryGetValue(pid, out var r) ? r : 0;
                return (sent, received);
            }
        }

        public void Dispose()
        {
            _session?.Dispose();
        }
    }

    // --- Static Data and State ---
    static string IgnoreFile = "ignored.txt";
    static string BlockFile = "blocked.txt";
    static string DomainFile = "domains.txt";
    static string CrashLogFile = "crash.log";

    static List<string> IgnoredProcesses = new List<string>();
    static List<string> BlockedIPs = new List<string>();
    static Dictionary<string, string> DomainCache = new Dictionary<string, string>();
    static Dictionary<string, DateTime> ConnectionStartTimes = new Dictionary<string, DateTime>();
    static EtwNetworkTracker? EtwTracker;
    static bool Running = true;

    // --- Main Entry Point ---
    static void Main()
    {
        // 1. Crash Handling
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            try { File.AppendAllText(CrashLogFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {e.ExceptionObject}\n\n"); }
            catch { }
            EtwTracker?.Dispose(); // Try to cleanup session on crash
        };

        // 2. Admin Check
        if (!IsAdministrator())
        {
            AnsiConsole.MarkupLine("[red]Requesting Administrator privileges (Required for ETW Kernel Tracing)...[/]");
            RestartAsAdmin();
            return;
        }

        // 3. Graceful Exit (Ctrl+C)
        Console.CancelKeyPress += (sender, e) =>
        {
            e.Cancel = true; // Stop Windows from killing us instantly
            Running = false;
        };

        // 4. Initialization
        LoadAllData();
        EtwTracker = new EtwNetworkTracker();
        
        try 
        {
            EtwTracker.Start();
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
            AnsiConsole.MarkupLine("[red]Error: Could not start ETW session. Try running 'logman stop TcpMonitorEtwSession_Persistent -ets' in Admin CMD.[/]");
            return;
        }

        DateTime lastRefresh = DateTime.Now;

        // 5. Main Loop
        while (Running)
        {
            if ((DateTime.Now - lastRefresh).TotalSeconds >= 2)
            {
                DrawScreen();
                lastRefresh = DateTime.Now;
            }

            if (Console.KeyAvailable)
            {
                string input = Console.ReadLine() ?? "";
                ProcessCommand(input.Trim().ToLower());
                DrawScreen();
                lastRefresh = DateTime.Now;
            }

            Thread.Sleep(100);
        }

        // 6. Cleanup
        AnsiConsole.MarkupLine("[yellow]Shutting down and saving data...[/]");
        EtwTracker?.Dispose();
        SaveAllData();
    }

    static void DrawScreen()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[bold cyan]TCP-MONITOR v3.7[/]"));
        int blockedCount = BlockedIPs.Count + GetFirewallBlockCount();
        AnsiConsole.MarkupLine($"[grey]Blocked: {blockedCount}  |  Ignored: {IgnoredProcesses.Count}  |  Press Ctrl+C or 'q' to exit[/]");

        var connections = GetTcpConnections();

        if (connections.Count == 0)
        {
            AnsiConsole.MarkupLine("\n[yellow]No active remote TCP connections found.[/]");
        }
        else
        {
            var table = new Table().Border(TableBorder.Rounded)
                .AddColumn(new TableColumn("[bold]#[/]").Centered())
                .AddColumn(new TableColumn("[bold]Process[/]"))
                .AddColumn(new TableColumn("[bold]PID[/]").Centered())
                .AddColumn(new TableColumn("[bold]Destination[/]"))
                .AddColumn(new TableColumn("[bold]Duration[/]").Centered())
                .AddColumn(new TableColumn("[bold]Sent[/]").RightAligned())
                .AddColumn(new TableColumn("[bold]Received[/]").RightAligned());

            for (int i = 0; i < connections.Count; i++)
            {
                var c = connections[i];
                table.AddRow(
                    (i + 1).ToString(),
                    c.ProcessName,
                    c.PID.ToString(),
                    $"{c.RemoteIP}\n[grey]{c.Domain}[/]",
                    c.Duration,
                    c.TotalSent,
                    c.TotalReceived
                );
            }
            AnsiConsole.WriteLine();
            AnsiConsole.Write(table);
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[grey]Connections: {connections.Count}  |  Auto-refresh: 2s  |  {DateTime.Now:HH:mm:ss}[/]");
        AnsiConsole.Write(new Rule("[bold green]Action[/]"));
        AnsiConsole.Markup("[bold yellow on grey] > [/] ");
    }

    static void ProcessCommand(string input)
    {
        if (string.IsNullOrEmpty(input)) return;

        if (input == "q" || input == "quit") { Running = false; return; }
        if (input == "help" || input == "?") { ShowHelp(); return; }
        if (input == "blocks") { InteractiveBlocksMenu(); return; }
        if (input == "ignored") { ManageIgnoredList(); return; }
        if (input == "kill" || input == "k") { KillProcessInteractive(); return; }
        if (input == "ignore") { IgnoreProcessInteractive(); return; }

        if (input.StartsWith("b") && int.TryParse(input[1..], out int blockIdx))
        {
            BlockIP(blockIdx); return;
        }

        AnsiConsole.MarkupLine("[red]Unknown command. Type 'help' for options.[/]");
        Thread.Sleep(700);
    }

    static void ShowHelp()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[bold yellow]Available Commands[/]"));

        var table = new Table().Border(TableBorder.Rounded)
            .AddColumn("[bold]Command[/]")
            .AddColumn("[bold]Description[/]");

        table.AddRow("b1, b2, b3...", "Block IP from that row number in the table");
        table.AddRow("blocks", "Manage blocked IPs and firewall rules");
        table.AddRow("kill / k", "Kill/terminate a process");
        table.AddRow("ignore", "Hide a process name from the list");
        table.AddRow("ignored", "Remove processes from the ignore list");
        table.AddRow("help / ?", "Show this help menu");
        table.AddRow("q / quit", "Exit application safely");

        AnsiConsole.Write(table);
        AnsiConsole.Prompt(new TextPrompt<string>("\nPress Enter to continue..."));
    }

    static void BlockIP(int index)
    {
        var connections = GetTcpConnections();
        if (index < 1 || index > connections.Count) return;

        string ip = connections[index - 1].RemoteIP;

        try
        {
            if (!BlockedIPs.Contains(ip)) { BlockedIPs.Add(ip); SaveBlockList(); }

            Type? policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (policyType == null) throw new InvalidOperationException("Could not find HNetCfg.FwPolicy2");
            dynamic fwPolicy = Activator.CreateInstance(policyType)!;
            
            Type? ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
            if (ruleType == null) throw new InvalidOperationException("Could not find HNetCfg.FWRule");
            dynamic rule = Activator.CreateInstance(ruleType)!;

            rule.Name = $"TCP-Monitor-Block-{ip}";
            rule.Description = $"Blocked via TCP-Monitor on {DateTime.Now}";
            rule.Protocol = 6; // TCP
            rule.Direction = 2; // Outbound
            rule.RemoteAddresses = ip;
            rule.Action = 0; // Block
            rule.Enabled = true;

            fwPolicy.Rules.Add(rule);
            AnsiConsole.MarkupLine($"[green]✓ Firewall rule added to block {ip}[/]");
            Thread.Sleep(800);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Failed to block IP. Check permissions.[/]");
            File.AppendAllText(CrashLogFile, $"[{DateTime.Now}] BlockIP Error: {ex}\n\n");
            Thread.Sleep(1000);
        }
    }

    static List<TcpConnectionInfo> GetTcpConnections()
    {
        var list = new List<TcpConnectionInfo>();
        var now = DateTime.Now;

        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return list;

            int rowCount = Marshal.ReadInt32(tcpTablePtr);
            IntPtr rowPtr = tcpTablePtr + 4;

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                if (row.dwState != 5) continue; // 5 = ESTABLISHED

                string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                if (remoteIP.StartsWith("127.") || remoteIP.StartsWith("0.0.0.0") || remoteIP.StartsWith("::1")) continue;

                int pid = (int)row.dwOwningPid;
                Process? proc = null;
                try { proc = Process.GetProcessById(pid); } catch { continue; }

                string procNameLower = proc.ProcessName.ToLower();
                if (IgnoredProcesses.Any(p => procNameLower.Contains(p))) continue;

                string key = $"{pid}-{remoteIP}:{row.dwRemotePort}";
                if (!ConnectionStartTimes.ContainsKey(key)) ConnectionStartTimes[key] = now;

                var duration = now - ConnectionStartTimes[key];
                var etw = EtwTracker?.GetStats(pid) ?? (0, 0);

                list.Add(new TcpConnectionInfo
                {
                    ProcessName = proc.ProcessName,
                    PID = pid,
                    RemoteIP = remoteIP,
                    Domain = GetCachedDomain(remoteIP),
                    Port = (int)row.dwRemotePort,
                    Duration = duration.ToString(@"hh\:mm\:ss"),
                    TotalSent = FormatBytes(etw.Sent),
                    TotalReceived = FormatBytes(etw.Received)
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTablePtr);
        }
        return list;
    }

    static string FormatBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB" };
        double db = bytes;
        int i = 0;
        while (db >= 1024 && i < units.Length - 1)
        {
            db /= 1024;
            i++;
        }
        return $"{db:N1} {units[i]}";
    }

    static string GetCachedDomain(string ip)
    {
        if (DomainCache.ContainsKey(ip)) return DomainCache[ip];
        try
        {
            var task = Task.Run(() => Dns.GetHostEntry(ip).HostName);
            if (task.Wait(700)) { DomainCache[ip] = task.Result; return task.Result; }
            DomainCache[ip] = $"(No DNS)"; return DomainCache[ip];
        }
        catch { DomainCache[ip] = $"(No DNS)"; return DomainCache[ip]; }
    }

    static void KillProcessInteractive()
    {
        var connections = GetTcpConnections();
        if (connections.Count == 0) return;

        var choices = connections.Select(c => $"{c.ProcessName} (PID {c.PID})").Distinct().ToList();
        choices.Add("Back");

        var selected = AnsiConsole.Prompt(new SelectionPrompt<string>().Title("[red]Kill process:[/]").AddChoices(choices));
        if (selected == "Back") return;

        int pid = int.Parse(selected.Split("PID ")[1].Replace(")", ""));
        var targetName = selected.Split(" (")[0];

        if (AnsiConsole.Confirm($"Terminate [red]{targetName}[/] (PID {pid})?"))
        {
            try { Process.GetProcessById(pid).Kill(); AnsiConsole.MarkupLine("[green]✓ Terminated[/]"); Thread.Sleep(500); }
            catch (Exception ex) { AnsiConsole.MarkupLine($"[red]{ex.Message}[/]"); Thread.Sleep(1000); }
        }
    }

    static void InteractiveBlocksMenu()
    {
        while (true)
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new Rule("[yellow]Blocked IPs / Firewall Rules[/]"));

            var local = BlockedIPs.ToList();
            var fw = GetFirewallBlockRules();

            if (local.Count == 0 && fw.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]Nothing currently blocked.[/]");
                AnsiConsole.Prompt(new TextPrompt<string>("Press Enter to return..."));
                return;
            }

            var choices = new List<string>();
            local.ForEach(ip => choices.Add($"[[Local-Only]] {ip}"));
            fw.ForEach(r => choices.Add($"[[Firewall]] {r}"));
            choices.Add("Back");

            var sel = AnsiConsole.Prompt(new SelectionPrompt<string>().Title("Select to UNBLOCK:").AddChoices(choices));
            if (sel == "Back") return;

            if (sel.StartsWith("[[Local-Only]]"))
            {
                BlockedIPs.Remove(sel.Replace("[[Local-Only]] ", ""));
                SaveBlockList();
            }
            else
            {
                RemoveFirewallRule(sel.Replace("[[Firewall]] ", ""));
            }
        }
    }

    static void IgnoreProcessInteractive()
    {
        var connections = GetTcpConnections();
        if (connections.Count == 0) return;

        var choices = connections.Select(c => c.ProcessName).Distinct().ToList();
        var selected = AnsiConsole.Prompt(new MultiSelectionPrompt<string>().Title("Hide these processes from view:").AddChoices(choices));

        foreach (var name in selected)
        {
            string lower = name.ToLower();
            if (!IgnoredProcesses.Contains(lower)) IgnoredProcesses.Add(lower);
        }
        SaveIgnoreList();
    }

    static void ManageIgnoredList()
    {
        if (IgnoredProcesses.Count == 0) { AnsiConsole.MarkupLine("Ignore list is empty."); Thread.Sleep(700); return; }
        var toRemove = AnsiConsole.Prompt(new MultiSelectionPrompt<string>().Title("[red]Remove from ignore list:[/]").AddChoices(IgnoredProcesses));
        foreach (var name in toRemove) IgnoredProcesses.Remove(name);
        SaveIgnoreList();
    }

    static bool IsAdministrator()
    {
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    static void RestartAsAdmin()
    {
        var startInfo = new ProcessStartInfo { FileName = Process.GetCurrentProcess().MainModule!.FileName, UseShellExecute = true, Verb = "runas" };
        try { Process.Start(startInfo); Environment.Exit(0); }
        catch { AnsiConsole.MarkupLine("[red]Admin rights refused.[/]"); }
    }

    static void LoadAllData()
    {
        if (File.Exists(IgnoreFile))
            IgnoredProcesses = File.ReadAllLines(IgnoreFile).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        else
            IgnoredProcesses = new List<string> { "chrome", "msedge", "firefox", "teams", "svchost", "system" };

        if (File.Exists(BlockFile))
            BlockedIPs = File.ReadAllLines(BlockFile).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();

        if (File.Exists(DomainFile))
        {
            foreach (var line in File.ReadAllLines(DomainFile))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2) DomainCache[parts[0]] = parts[1];
            }
        }
    }

    static void SaveAllData()
    {
        SaveIgnoreList();
        SaveBlockList();
        try { File.WriteAllLines(DomainFile, DomainCache.Select(kv => $"{kv.Key}={kv.Value}")); } catch { }
    }

    static void SaveIgnoreList() => File.WriteAllLines(IgnoreFile, IgnoredProcesses);
    static void SaveBlockList() => File.WriteAllLines(BlockFile, BlockedIPs);

    static int GetFirewallBlockCount()
    {
        try
        {
            var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"(Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'TCP-Monitor-Block-*'}).Count\"",
                    UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true
                }
            };
            p.Start();
            string output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit();
            return int.TryParse(output, out int c) ? c : 0;
        }
        catch { return 0; }
    }

    static List<string> GetFirewallBlockRules()
    {
        var result = new List<string>();
        try
        {
            var p = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Get-NetFirewallRule | Where-Object {$_.DisplayName -like 'TCP-Monitor-Block-*'} | Select-Object -ExpandProperty DisplayName\"",
                    UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true
                }
            };
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            result = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList();
        }
        catch { }
        return result;
    }

    static void RemoveFirewallRule(string ruleName)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -Command \"Remove-NetFirewallRule -DisplayName '{ruleName}' -Confirm:$false\"",
                CreateNoWindow = true,
                UseShellExecute = false
            })?.WaitForExit();
            AnsiConsole.MarkupLine($"[green]✓ Rule {ruleName} removed.[/]");
            Thread.Sleep(600);
        }
        catch { }
    }
}

class TcpConnectionInfo
{
    public string ProcessName { get; set; } = "";
    public int PID { get; set; }
    public string RemoteIP { get; set; } = "";
    public string Domain { get; set; } = "";
    public int Port { get; set; }
    public string Duration { get; set; } = "";
    public string TotalSent { get; set; } = "";
    public string TotalReceived { get; set; } = "";
}