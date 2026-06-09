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
        private readonly GeoIpService _geoIpService;
        private readonly SystemSettingsService _systemSettingsService;
        private readonly DispatcherTimer _timer;
        private readonly DateTime _startTime = DateTime.Now;

        private Dictionary<string, BlockedIPMetadata> _blockedIPsDict = new();
        private HashSet<string> _ignoredAppsSet = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);

        // Smart-diff: keyed by ConnectionKey for in-place updates
        private readonly Dictionary<string, ConnectionInfo> _connectionMap = new();

        // Fix #10: Cache the last OS-queried connection list so that SearchFilter changes
        // apply a client-side filter without triggering expensive OS calls.
        private List<ConnectionInfo> _latestConnections = new();

        public ObservableCollection<ConnectionInfo> Connections { get; } = new();
        public ObservableCollection<BlockedIPEntry> BlockedIPs { get; } = new();
        public ObservableCollection<IgnoredAppEntry> IgnoredApps { get; } = new();
        public ObservableCollection<AlertEntry> Alerts { get; } = new();

        private bool _isMonitorActive;
        public bool IsMonitorActive { get => _isMonitorActive; set => SetProperty(ref _isMonitorActive, value); }

        private ConnectionInfo? _selectedConnection;
        public ConnectionInfo? SelectedConnection
        {
            get => _selectedConnection;
            set
            {
                if (SetProperty(ref _selectedConnection, value))
                {
                    OnPropertyChanged(nameof(HasSelectedConnection));
                }
            }
        }

        public bool HasSelectedConnection => SelectedConnection != null;

        public bool IsConnectionDriven
        {
            get => _networkMonitor.MonitoringStrategy == ProcessMonitoringStrategy.ConnectionDriven;
            set
            {
                if (value)
                {
                    _networkMonitor.SetMonitoringStrategy(ProcessMonitoringStrategy.ConnectionDriven);
                    OnPropertyChanged(nameof(IsConnectionDriven));
                    OnPropertyChanged(nameof(IsProcessStartEtw));
                    AddAlert("Switched process monitoring to: Connection-Driven", AlertSeverity.Info);
                }
            }
        }

        public bool IsProcessStartEtw
        {
            get => _networkMonitor.MonitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw;
            set
            {
                if (value)
                {
                    _networkMonitor.SetMonitoringStrategy(ProcessMonitoringStrategy.ProcessStartEtw);
                    OnPropertyChanged(nameof(IsConnectionDriven));
                    OnPropertyChanged(nameof(IsProcessStartEtw));
                    AddAlert("Switched process monitoring to: ETW Process Start", AlertSeverity.Info);
                }
            }
        }

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

        private int _refreshInterval = 2;
        public int RefreshInterval
        {
            get => _refreshInterval;
            set
            {
                if (SetProperty(ref _refreshInterval, value) && value > 0)
                {
                    _timer.Interval = TimeSpan.FromSeconds(value);
                }
            }
        }

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
                    // Fix #10: Apply filter client-side on the cached connection list —
                    // do NOT trigger a full OS query just because the user typed a character.
                    ApplyFilterAndUpdate(_latestConnections);
                }
            }
        }

        private string _statusMessage = "Initializing...";
        public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

        public bool IsLanguageSyncEnabled
        {
            get => _systemSettingsService.IsLanguageSyncEnabled();
            set
            {
                _systemSettingsService.SetLanguageSyncEnabled(value);
                if (!value) _systemSettingsService.StopProcess("SettingSyncHost");
                OnPropertyChanged(nameof(IsLanguageSyncEnabled));
                AddAlert($"Language Sync {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsWidgetsEnabled
        {
            get => _systemSettingsService.IsWidgetsEnabled();
            set
            {
                _systemSettingsService.SetWidgetsEnabled(value);
                if (!value) _systemSettingsService.StopProcess("Widgets");
                OnPropertyChanged(nameof(IsWidgetsEnabled));
                AddAlert($"Windows Widgets {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsSearchHostEnabled
        {
            get => _systemSettingsService.IsSearchHostEnabled();
            set
            {
                _systemSettingsService.SetSearchHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("SearchHost");
                OnPropertyChanged(nameof(IsSearchHostEnabled));
                AddAlert($"SearchHost Box {(value ? "enabled" : "disabled")}", AlertSeverity.Info);
            }
        }

        public bool IsStartMenuExperienceHostEnabled
        {
            get => _systemSettingsService.IsStartMenuExperienceHostEnabled();
            set
            {
                _systemSettingsService.SetStartMenuExperienceHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("StartMenuExperienceHost");
                OnPropertyChanged(nameof(IsStartMenuExperienceHostEnabled));
                AddAlert($"StartMenuExperienceHost {(value ? "enabled" : "removed")}", AlertSeverity.Info);
            }
        }

        public bool IsShellExperienceHostEnabled
        {
            get => _systemSettingsService.IsShellExperienceHostEnabled();
            set
            {
                _systemSettingsService.SetShellExperienceHostEnabled(value);
                if (!value) _systemSettingsService.StopProcess("ShellExperienceHost");
                OnPropertyChanged(nameof(IsShellExperienceHostEnabled));
                AddAlert($"ShellExperienceHost {(value ? "enabled" : "removed")}", AlertSeverity.Info);
            }
        }

        public bool IsWebView2Blocked
        {
            get => _systemSettingsService.IsWebView2Blocked();
            set
            {
                _systemSettingsService.SetWebView2Blocked(value);
                if (value)
                {
                    string path = _systemSettingsService.FindWebView2Path();
                    if (!string.IsNullOrEmpty(path))
                    {
                        _firewallService.ApplyWebView2NetworkBlock(path);
                        AddAlert($"Proactively blocked WebView2 outbound network (Path: {path})", AlertSeverity.Info);
                    }
                    else
                    {
                        AddAlert("Failed to locate msedgewebview2.exe on this system.", AlertSeverity.Warning);
                    }
                }
                else
                {
                    _firewallService.RemoveWebView2NetworkBlock();
                    AddAlert("Allowed WebView2 outbound network requests.", AlertSeverity.Info);
                }
                OnPropertyChanged(nameof(IsWebView2Blocked));
            }
        }

        // Commands
        public RelayCommand<object> BlockIPCommand { get; }
        public RelayCommand<string> UnblockIPCommand { get; }
        public RelayCommand<string> IgnoreAppCommand { get; }
        public RelayCommand<string> UnignoreAppCommand { get; }
        public RelayCommand<object> StopAppCommand { get; }
        public RelayCommand ClearAlertsCommand { get; }
        public RelayCommand RefreshCommand { get; }
        public RelayCommand ExportLogCommand { get; }
        public RelayCommand DeselectConnectionCommand { get; }

        public MainViewModel()
        {
            // Fix #8: Use DataService.ResolveBaseDir() indirectly — the DataService now
            // computes the correct path. Crash log uses the same resolved directory.
            string? exeDir = Path.GetDirectoryName(Environment.ProcessPath
                             ?? Process.GetCurrentProcess().MainModule?.FileName);
            string logDir  = string.IsNullOrEmpty(exeDir) ? AppContext.BaseDirectory : exeDir;

            // Walk up from bin/Debug/net8.0-windows/ if we're in a build output dir
            string candidate = Path.GetFullPath(Path.Combine(logDir, "..", "..", "..", ".."));
            if (Directory.Exists(candidate)) logDir = candidate;

            Action<string> logError = msg =>
            {
                try { File.AppendAllText(Path.Combine(logDir, "crash.log"), $"[{DateTime.Now:s}] {msg}\n"); }
                catch { /* swallow if we can't even write the crash log */ }
            };

            _geoIpService         = new GeoIpService();
            _dataService          = new DataService(logError);
            _firewallService      = new FirewallService(logError);
            _systemSettingsService= new SystemSettingsService(logError);
            _networkMonitor       = new NetworkMonitorService(logError, _geoIpService);

            _networkMonitor.OnProactiveAlert = alert =>
            {
                Application.Current?.Dispatcher?.BeginInvoke(new Action(() =>
                {
                    AddAlertEntry(alert);
                }));
            };

            // Fix: StopAppCommand uses object parameter so WPF string→int conversion isn't needed
            BlockIPCommand         = new RelayCommand<object>(ExecuteBlockIP);
            UnblockIPCommand       = new RelayCommand<string>(ExecuteUnblockIP);
            IgnoreAppCommand       = new RelayCommand<string>(ExecuteIgnoreApp);
            UnignoreAppCommand     = new RelayCommand<string>(ExecuteUnignoreApp);
            StopAppCommand         = new RelayCommand<object>(ExecuteStopApp);
            ClearAlertsCommand     = new RelayCommand(_ => Alerts.Clear());
            RefreshCommand         = new RelayCommand(_ => Timer_Tick(null, EventArgs.Empty));
            ExportLogCommand       = new RelayCommand(_ => ExecuteExportLog());
            DeselectConnectionCommand = new RelayCommand(_ => SelectedConnection = null);

            // Check admin status
            IsAdmin = CheckIsAdmin();

            LoadData();

            // Proactive WebView2 Network Block on Startup
            try
            {
                if (_systemSettingsService.IsWebView2Blocked())
                {
                    string path = _systemSettingsService.FindWebView2Path();
                    if (!string.IsNullOrEmpty(path))
                    {
                        _firewallService.ApplyWebView2NetworkBlock(path);
                    }
                }
            }
            catch { }

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

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(_refreshInterval) };
            _timer.Tick += Timer_Tick;
            _timer.Start();
        }

        private static bool CheckIsAdmin()
        {
            try
            {
                var identity  = WindowsIdentity.GetCurrent();
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
            // Note: We no longer auto-populate process names from _blockedIPs to avoid
            // aggressive kill-loops for shared components like WebView2.
            // Process name blocking is now an explicit, separate action if added in the future.
            foreach (var kvp in _blockedIPsDict)
            {
                if (!IPAddress.TryParse(kvp.Key, out _))
                    _blockedProcessNames.Add(kvp.Key); // treat non-IP key as process name
            }
        }

        private void SyncObservables()
        {
            RebuildBlockedProcessNames();

            BlockedIPs.Clear();
            foreach (var kvp in _blockedIPsDict.OrderBy(x => x.Key))
                BlockedIPs.Add(new BlockedIPEntry { IP = kvp.Key, Application = kvp.Value.Application, Timestamp = kvp.Value.Timestamp });

            BlockedCount = BlockedIPs.Count;

            IgnoredApps.Clear();
            foreach (var app in _ignoredAppsSet.OrderBy(x => x))
                IgnoredApps.Add(new IgnoredAppEntry { Application = app });

            // Refresh firewall rule count (cached — no expensive COM enumeration unless invalidated)
            try { FirewallRuleCount = _firewallService.GetRuleCount(); }
            catch { /* non-critical */ }
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            IsMonitorActive = _networkMonitor.IsRunning;

            // Update uptime
            UptimeDisplay  = (DateTime.Now - _startTime).ToString(@"hh\:mm\:ss");
            LastRefreshTime = DateTime.Now.ToString("HH:mm:ss");

            // Update total traffic stats
            var traffic = _networkMonitor.GetTotalTrafficStats();
            TotalUpload   = FormatBytes(traffic.TotalSent);
            TotalDownload = FormatBytes(traffic.TotalReceived);

            // Query OS for fresh connections
            var freshConns = _networkMonitor.GetConnections(_ignoredAppsSet, _blockedIPsDict, _blockedProcessNames);

            // Fix #10: Store the unfiltered OS result so SearchFilter can apply client-side.
            _latestConnections = freshConns;

            var alerts = _networkMonitor.AutoEnforce(freshConns, _firewallService, _blockedIPsDict, _blockedProcessNames);

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

            // Apply filter (client-side) and smart-diff update
            ApplyFilterAndUpdate(freshConns);
            ConnectionCount = Connections.Count;
        }

        /// <summary>
        /// Fix #10: Applies the current search filter to a connection list (client-side),
        /// then drives the smart-diff update. Called from Timer_Tick AND from SearchFilter setter.
        /// </summary>
        private void ApplyFilterAndUpdate(List<ConnectionInfo> source)
        {
            IEnumerable<ConnectionInfo> filtered = source;

            if (!string.IsNullOrWhiteSpace(_searchFilter))
            {
                string filter = _searchFilter.ToLower();
                filtered = source.Where(c =>
                    c.ApplicationName.ToLower().Contains(filter) ||
                    c.Destination.Contains(filter) ||
                    c.Domain.ToLower().Contains(filter) ||
                    c.Location.ToLower().Contains(filter)
                );
            }

            SmartUpdateConnections(filtered.ToList());
            ConnectionCount = Connections.Count;
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

                        // If this was the selected connection, update the selection reference to the new instance
                        // so the details panel updates in real-time with the latest bytes and durations.
                        if (SelectedConnection != null && SelectedConnection.ConnectionKey == conn.ConnectionKey)
                        {
                            SelectedConnection = conn;
                        }
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

                    if (SelectedConnection != null && SelectedConnection.ConnectionKey == key)
                    {
                        SelectedConnection = null;
                    }
                }
            }
        }

        /// <summary>
        /// Fix: Block command now correctly receives ConnectionInfo or "IP|AppName" string.
        /// </summary>
        private void ExecuteBlockIP(object? parameter)
        {
            if (parameter == null) return;

            string ip  = "";
            string app = "Unknown";

            if (parameter is ConnectionInfo conn)
            {
                ip  = conn.Destination;
                app = conn.ApplicationName;
            }
            else if (parameter is string ipAndApp)
            {
                if (string.IsNullOrWhiteSpace(ipAndApp)) return;
                var parts = ipAndApp.Split('|');
                ip  = parts[0].Trim();
                app = parts.Length > 1 ? parts[1].Trim() : "Unknown";
            }
            else
            {
                return;
            }

            if (!IPAddress.TryParse(ip, out _)) return;

            if (!_blockedIPsDict.ContainsKey(ip))
            {
                if (_firewallService.AddBlockRule(ip, app))
                {
                    _blockedIPsDict[ip] = new BlockedIPMetadata { Application = app, Timestamp = DateTime.Now };
                    _dataService.SaveBlocked(_blockedIPsDict);
                    _networkMonitor.ResetConnectionsToIp(ip); // Sever any existing active connections
                    SyncObservables();
                    AddAlert($"Blocked {ip} ({app})", AlertSeverity.Warning);
                }
                else
                {
                    AddAlert($"Failed to block {ip}. Ensure app is running as Administrator.", AlertSeverity.Critical);
                }
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
                process.Kill(entireProcessTree: true); // Kill tree for more effective termination
                AddAlert($"Stopped {name} and its children (PID {pid})", AlertSeverity.Warning);
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 5) // Access Denied
            {
                AddAlert($"Access denied to stop PID {pid}. System or protected process?", AlertSeverity.Critical);
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
            // Stop the timer to prevent post-disposal tick events
            _timer.Stop();
            _timer.Tick -= Timer_Tick;
            _networkMonitor.Stop();
            _dataService.SaveBlocked(_blockedIPsDict);
            _dataService.SaveIgnored(_ignoredAppsSet);
            // Fix #15: Dispose GeoIpService (and its HttpClient) on shutdown
            _geoIpService.Dispose();
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
