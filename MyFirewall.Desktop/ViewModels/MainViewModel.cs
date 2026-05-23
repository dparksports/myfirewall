using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
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

        private Dictionary<string, string> _blockedIPsDict = new();
        private HashSet<string> _ignoredAppsSet = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<string> _blockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
        private HashSet<int> _autoKilledPids = new();

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

        public RelayCommand<string> BlockIPCommand { get; }
        public RelayCommand<string> UnblockIPCommand { get; }
        public RelayCommand<string> IgnoreAppCommand { get; }
        public RelayCommand<string> UnignoreAppCommand { get; }
        public RelayCommand<int> StopAppCommand { get; }
        public RelayCommand ClearAlertsCommand { get; }

        public MainViewModel()
        {
            Action<string> logError = msg => System.IO.File.AppendAllText("crash.log", $"[{DateTime.Now:s}] {msg}\n");

            _dataService = new DataService(logError);
            _firewallService = new FirewallService(logError);
            _networkMonitor = new NetworkMonitorService(logError, new GeoIpService());

            BlockIPCommand = new RelayCommand<string>(ExecuteBlockIP);
            UnblockIPCommand = new RelayCommand<string>(ExecuteUnblockIP);
            IgnoreAppCommand = new RelayCommand<string>(ExecuteIgnoreApp);
            UnignoreAppCommand = new RelayCommand<string>(ExecuteUnignoreApp);
            StopAppCommand = new RelayCommand<int>(ExecuteStopApp);
            ClearAlertsCommand = new RelayCommand(_ => Alerts.Clear());

            LoadData();

            _networkMonitor.Start();

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _timer.Tick += Timer_Tick;
            _timer.Start();
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
        }

        private void Timer_Tick(object? sender, EventArgs e)
        {
            IsMonitorActive = _networkMonitor.IsRunning;

            var newConns = _networkMonitor.GetConnections(_ignoredAppsSet, _blockedIPsDict, _blockedProcessNames);
            
            var alerts = _networkMonitor.AutoEnforce(newConns, _firewallService, _blockedIPsDict, _blockedProcessNames, _autoKilledPids);
            
            bool saveNeeded = false;
            foreach (var alert in alerts)
            {
                Alerts.Add(alert);
                if (Alerts.Count > 10) Alerts.RemoveAt(0);
                saveNeeded = true;
            }

            if (saveNeeded)
            {
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
            }

            // Sync connection list without flickering
            ConnectionCount = newConns.Count;
            Connections.Clear();
            foreach (var c in newConns) Connections.Add(c);
        }

        private void ExecuteBlockIP(string? ipAndApp)
        {
            if (string.IsNullOrWhiteSpace(ipAndApp)) return;
            var parts = ipAndApp.Split('|');
            string ip = parts[0];
            string app = parts.Length > 1 ? parts[1] : "Unknown";

            if (!IPAddress.TryParse(ip, out _)) return;

            if (!_blockedIPsDict.ContainsKey(ip))
            {
                _blockedIPsDict[ip] = app;
                _firewallService.AddBlockRule(ip, app);
                _dataService.SaveBlocked(_blockedIPsDict);
                SyncObservables();
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
                Timer_Tick(null, EventArgs.Empty); // refresh right away
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
                Timer_Tick(null, EventArgs.Empty); // refresh right away
            }
        }

        private void ExecuteStopApp(int pid)
        {
            try
            {
                Process.GetProcessById(pid).Kill();
                Alerts.Add(new AlertEntry { Message = $"Stopped Process {pid} manually" });
            }
            catch (Exception ex)
            {
                Alerts.Add(new AlertEntry { Message = $"Failed to stop process: {ex.Message}" });
            }
        }

        public void Shutdown()
        {
            _networkMonitor.Stop();
        }
    }
}
