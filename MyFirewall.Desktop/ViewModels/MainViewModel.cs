using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using MyFirewall.Desktop.Models;
using MyFirewall.Desktop.Services;

namespace MyFirewall.Desktop.ViewModels
{
    public class MainViewModel : ObservableObject
    {
        private readonly NetworkMonitorService _networkMonitor;
        private readonly FirewallService _firewallService;
        private readonly DataService _dataService;
        private readonly DispatcherTimer _timer;
        private readonly DateTime _startTime = DateTime.Now;
        private int _pruneCounter;

        private Dictionary<string, string> _blockedIPsDict = new();
        private HashSet<string> _ignoredAppsSet = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<int> _autoKilledPids = new();

        // Smart-diff: keyed by ConnectionKey for in-place updates
        private readonly Dictionary<string, ConnectionInfo> _connectionMap = new();

        public ObservableCollection<ConnectionInfo> Connections { get; } = new();
        public ObservableCollection<BlockedIPEntry> BlockedIPs { get; } = new();
        public ObservableCollection<IgnoredAppEntry> IgnoredApps { get; } = new();
        public ObservableCollection<AlertEntry> Alerts { get; } = new();

        private bool _isMonitorActive;
        public bool IsMonitorActive { get => _isMonitorActive; set => SetProperty(ref _isMonitorActive, value); }

        private int _connectionCount;
        public int ConnectionCount { get => _connectionCount; set => SetProperty(ref _connectionCount, value); }

        private int _blockedCount;
        public int BlockedCount { get => _blockedCount; set => SetProperty(ref _blockedCount, value); }

        private string _totalUpload = "0 B";
        public string TotalUpload { get => _totalUpload; set => SetProperty(ref _totalUpload, value); }

        private string _totalDownload = "0 B";
        public string TotalDownload { get => _totalDownload; set => SetProperty(ref _totalDownload, value); }

        private string _uptimeDisplay = "00:00:00";
        public string UptimeDisplay { get => _uptimeDisplay; set => SetProperty(ref _uptimeDisplay, value); }

        private string _lastRefreshTime = "--:--:--";
        public string LastRefreshTime { get => _lastRefreshTime; set => SetProperty(ref _lastRefreshTime, value); }

        private int _firewallRuleCount;
        public int FirewallRuleCount { get => _firewallRuleCount; set => SetProperty(ref _firewallRuleCount, value); }

        private bool _isAdmin;
        public bool IsAdmin { get => _isAdmin; set => SetProperty(ref _isAdmin, value); }

        private string _searchFilter = "";
        public string SearchFilter
        {
            get => _searchFilter;
            set
            {
                if (SetProperty(ref _searchFilter, value))
                {
                    // Force a refresh when search text changes
                    Timer_Tick(null, EventArgs.Empty);
                }
            }
        }

        private string _statusMessage = "Initializing...";
        public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

        // Commands
        public RelayCommand<object> BlockIPCommand { get; }
        public RelayCommand<string> UnblockIPCommand { get; }
        public RelayCommand<string> IgnoreAppCommand { get; }
        public RelayCommand<string> UnignoreAppCommand { get; }
        public RelayCommand<object> StopAppCommand { get; }
        public RelayCommand ClearAlertsCommand { get; }
        public RelayCommand RefreshCommand { get; }
        public RelayCommand ExportLogCommand { get; }

        public MainViewModel()
        {
            string logDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            Action<string> logError = msg =>
            {
                try { File.AppendAllText(Path.Combine(logDir, "crash.log"), $"[{DateTime.Now:s}] {msg}\n"); }
                catch { /* swallow if we can't even write the crash log */ }
            };

            _dataService = new DataService(logError);
            _firewallService = new FirewallService(logError);
            _networkMonitor = new NetworkMonitorService(logError, new GeoIpService());

            // Fix: StopAppCommand uses object parameter so WPF string→int conversion isn't needed
            BlockIPCommand = new RelayCommand<object>(ExecuteBlockIP);
            UnblockIPCommand = new RelayCommand<string>(ExecuteUnblockIP);
            IgnoreAppCommand = new RelayCommand<string>(ExecuteIgnoreApp);
            UnignoreAppCommand = new RelayCommand<string>(ExecuteUnignoreApp);
            StopAppCommand = new RelayCommand<object>(ExecuteStopApp);
            ClearAlertsCommand = new RelayCommand(_ => Alerts.Clear());
            RefreshCommand = new RelayCommand(_ => Timer_Tick(null, EventArgs.Empty));
            ExportLogCommand = new RelayCommand(_ => ExecuteExportLog());

            // Check admin status
            IsAdmin = CheckIsAdmin();

            LoadData();

            try
            {
                _networkMonitor.Start();
                StatusMessage = "Network monitor active";
            }
            catch (Exception ex)
            {
                StatusMessage = $"ETW failed: {ex.Message}";
                AddAlert($"Failed to start network monitor: {ex.Message}", AlertSeverity.Critical);
            }

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _timer.Tick += Timer_Tick;
            _timer.Start();
        }

        private static bool CheckIsAdmin()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private void LoadData()
        {
            var data = _dataService.LoadData();
            _blockedIPsDict = data.BlockedIPs;
            _ignoredAppsSet = data.IgnoredApps;

            SyncObservables();
        }

        private void RebuildBlockedProcessNames()
        {
            _blockedProcessNames.Clear();
            foreach (var kvp in _blockedIPsDict)
            {
                if (kvp.Value != "Unknown") _blockedProcessNames.Add(kvp.Value);
            }
        }

        private void SyncObservables()
        {
            RebuildBlockedProcessNames();

            BlockedIPs.Clear();
            foreach (var kvp in _blockedIPsDict.OrderBy(x => x.Key))
                BlockedIPs.Add(new BlockedIPEntry { IP = kvp.Key, Application = kvp.Value });

            BlockedCount = BlockedIPs.Count;

            IgnoredApps.Clear();
            foreach (var app in _ignoredAppsSet.OrderBy(x => x))
                IgnoredApps.Add(new IgnoredAppEntry { Application = app });

            // Refresh firewall rule count
            try { FirewallRuleCount = _firewallService.GetRuleCount(); }
            catch { /* non-critical */ }
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            IsMonitorActive = _networkMonitor.IsRunning;

            // Update uptime
            UptimeDisplay = (DateTime.Now - _startTime).ToString(@"hh\:mm\:ss");
            LastRefreshTime = DateTime.Now.ToString("HH:mm:ss");

            // Update total traffic stats
            var traffic = _networkMonitor.GetTotalTrafficStats();
            TotalUpload = FormatBytes(traffic.TotalSent);
            TotalDownload = FormatBytes(traffic.TotalReceived);

            var newConns = _networkMonitor.GetConnections(_ignoredAppsSet, _blockedIPsDict, _blockedProcessNames);

            // Apply search filter
            if (!string.IsNullOrWhiteSpace(_searchFilter))
            {
                string filter = _searchFilter.ToLower();
                newConns = newConns.Where(c =>
                    c.ApplicationName.ToLower().Contains(filter) ||
                    c.Destination.Contains(filter) ||
                    c.Domain.ToLower().Contains(filter) ||
                    c.Location.ToLower().Contains(filter)
                ).ToList();
            }

            var alerts = _networkMonitor.AutoEnforce(newConns, _firewallService, _blockedIPsDict, _blockedProcessNames, _autoKilledPids);

            bool saveNeeded = false;
            foreach (var alert in alerts)
            {
                AddAlertEntry(alert);
                saveNeeded = true;
            }

            if (saveNeeded)
            {
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
            }

            // Smart-diff update: only add/remove/update changed connections (eliminates flicker)
            SmartUpdateConnections(newConns);
            ConnectionCount = Connections.Count;

            // Prune stale auto-killed PIDs every ~30 seconds (10 ticks at 3s interval)
            _pruneCounter++;
            if (_pruneCounter >= 10)
            {
                _pruneCounter = 0;
                NetworkMonitorService.PruneStaleKilledPids(_autoKilledPids);
            }
        }

        /// <summary>
        /// Smart-diff connection list: update in-place, add new, remove stale.
        /// This eliminates DataGrid flicker from Clear() + re-add.
        /// </summary>
        private void SmartUpdateConnections(List<ConnectionInfo> newConns)
        {
            var newKeys = new HashSet<string>();

            foreach (var conn in newConns)
            {
                newKeys.Add(conn.ConnectionKey);

                if (_connectionMap.TryGetValue(conn.ConnectionKey, out var existing))
                {
                    // Update existing entry's mutable fields in-place
                    int idx = Connections.IndexOf(existing);
                    if (idx >= 0)
                    {
                        Connections[idx] = conn;
                        _connectionMap[conn.ConnectionKey] = conn;
                    }
                }
                else
                {
                    // New connection
                    Connections.Add(conn);
                    _connectionMap[conn.ConnectionKey] = conn;
                }
            }

            // Remove connections no longer present
            var staleKeys = _connectionMap.Keys.Except(newKeys).ToList();
            foreach (var key in staleKeys)
            {
                if (_connectionMap.TryGetValue(key, out var stale))
                {
                    Connections.Remove(stale);
                    _connectionMap.Remove(key);
                }
            }
        }

        /// <summary>
        /// Fix: Block command now correctly receives ConnectionInfo or "IP|AppName" string.
        /// </summary>
        private void ExecuteBlockIP(object? parameter)
        {
            if (parameter == null) return;

            string ip = "";
            string app = "Unknown";

            if (parameter is ConnectionInfo conn)
            {
                ip = conn.Destination;
                app = conn.ApplicationName;
            }
            else if (parameter is string ipAndApp)
            {
                if (string.IsNullOrWhiteSpace(ipAndApp)) return;
                var parts = ipAndApp.Split('|');
                ip = parts[0].Trim();
                app = parts.Length > 1 ? parts[1].Trim() : "Unknown";
            }
            else
            {
                return;
            }

            if (!IPAddress.TryParse(ip, out _)) return;

            if (!_blockedIPsDict.ContainsKey(ip))
            {
                _blockedIPsDict[ip] = app;
                _firewallService.AddBlockRule(ip, app);
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
                AddAlert($"Blocked {ip} ({app})", AlertSeverity.Warning);
            }
        }

        private void ExecuteUnblockIP(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;

            if (_blockedIPsDict.Remove(ip))
            {
                _firewallService.RemoveBlockRule(ip);
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
                AddAlert($"Unblocked {ip}", AlertSeverity.Info);
            }
        }

        private void ExecuteIgnoreApp(string? app)
        {
            if (string.IsNullOrWhiteSpace(app)) return;
            app = app.ToLower();

            if (_ignoredAppsSet.Add(app))
            {
                _dataService.SaveIgnored(_ignoredAppsSet);
                SyncObservables();
                AddAlert($"Now ignoring {app}", AlertSeverity.Info);
            }
        }

        private void ExecuteUnignoreApp(string? app)
        {
            if (string.IsNullOrWhiteSpace(app)) return;
            app = app.ToLower();

            if (_ignoredAppsSet.Remove(app))
            {
                _dataService.SaveIgnored(_ignoredAppsSet);
                SyncObservables();
                AddAlert($"Restored {app}", AlertSeverity.Info);
            }
        }

        /// <summary>
        /// Fix: StopAppCommand now accepts object and handles string-to-int conversion explicitly.
        /// WPF passes CommandParameter as string even when binding to an int property.
        /// </summary>
        private void ExecuteStopApp(object? parameter)
        {
            int pid;
            if (parameter is int i) pid = i;
            else if (parameter is string s && int.TryParse(s, out int parsed)) pid = parsed;
            else
            {
                AddAlert("Failed to stop process: invalid PID", AlertSeverity.Critical);
                return;
            }

            try
            {
                var process = Process.GetProcessById(pid);
                string name = process.ProcessName;
                process.Kill();
                AddAlert($"Stopped {name} (PID {pid})", AlertSeverity.Warning);
            }
            catch (Exception ex)
            {
                AddAlert($"Failed to stop PID {pid}: {ex.Message}", AlertSeverity.Critical);
            }
        }

        private void ExecuteExportLog()
        {
            try
            {
                var alertMessages = Alerts.Select(a => $"[{a.Timestamp}] {a.Message}");
                string path = _dataService.ExportReport(_blockedIPsDict, _ignoredAppsSet, alertMessages);
                if (!string.IsNullOrEmpty(path))
                {
                    AddAlert($"Report exported to {Path.GetFileName(path)}", AlertSeverity.Info);
                    // Open the report file
                    Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
                }
            }
            catch (Exception ex)
            {
                AddAlert($"Export failed: {ex.Message}", AlertSeverity.Critical);
            }
        }

        private void AddAlert(string message, AlertSeverity severity)
        {
            AddAlertEntry(new AlertEntry { Message = message, Severity = severity });
        }

        private void AddAlertEntry(AlertEntry alert)
        {
            Alerts.Insert(0, alert); // newest first
            while (Alerts.Count > 20) Alerts.RemoveAt(Alerts.Count - 1);
        }

        public void Shutdown()
        {
            // Fix: Stop the timer to prevent post-disposal tick events
            _timer.Stop();
            _timer.Tick -= Timer_Tick;
            _networkMonitor.Stop();
            _dataService.SaveBlocked(_blockedIPsDict);
            _dataService.SaveIgnored(_ignoredAppsSet);
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
