using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using MyFirewall.Desktop.Models;

namespace MyFirewall.Desktop.Services
{
    public enum ProcessMonitoringStrategy
    {
        ConnectionDriven,
        ProcessStartEtw
    }

    public class NetworkMonitorService : IDisposable
    {
        private static readonly string SessionName = KernelTraceEventParser.KernelSessionName;
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        private readonly object _lock = new();
        private readonly Action<string> _logError;
        private readonly GeoIpService _geoIpService;
        private readonly ProcessMetadataService _metadataService = new();
        private bool _disposed;

        private readonly Dictionary<string, DateTime> _connectionStartTimes = new();
        private readonly Dictionary<string, string> _socketHistory = new();
        public bool IsRunning { get; private set; }

        private ProcessMonitoringStrategy _monitoringStrategy = ProcessMonitoringStrategy.ProcessStartEtw;
        public ProcessMonitoringStrategy MonitoringStrategy => _monitoringStrategy;
        public Action<AlertEntry>? OnProactiveAlert { get; set; }
        private readonly HashSet<int> _proactiveEvaluatedPids = new();

        public NetworkMonitorService(Action<string> logError, GeoIpService geoIpService)
        {
            _logError = logError;
            _geoIpService = geoIpService;
        }

        /// <summary>
        /// Fix #11: Strategy switch runs Stop+Start on a background Task so the UI is never
        /// blocked by the 500ms ETW session cleanup sleep.
        /// </summary>
        public void SetMonitoringStrategy(ProcessMonitoringStrategy strategy)
        {
            if (_monitoringStrategy == strategy) return;
            _monitoringStrategy = strategy;

            if (IsRunning)
            {
                // Run the stop+restart off the UI thread so Thread.Sleep(500) doesn't block WPF.
                Task.Run(() =>
                {
                    try
                    {
                        Stop();
                        Start();
                    }
                    catch (Exception ex)
                    {
                        _logError($"SetMonitoringStrategy restart: {ex.Message}");
                    }
                });
            }
        }

        public void Start()
        {
            try
            {
                using (var existing = new TraceEventSession(SessionName))
                {
                    existing.Stop(noThrow: true);
                }
                Thread.Sleep(500);

                lock (_lock)
                {
                    _proactiveEvaluatedPids.Clear();
                }

                _session = new TraceEventSession(SessionName) { StopOnDispose = true };

                var keywords = KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.Process;
                _session.EnableKernelProvider(keywords);

                _session.Source.Kernel.TcpIpSend += data =>
                {
                    lock (_lock) _bytesSent[data.ProcessID] = _bytesSent.GetValueOrDefault(data.ProcessID) + data.size;
                };
                _session.Source.Kernel.TcpIpRecv += data =>
                {
                    lock (_lock) _bytesReceived[data.ProcessID] = _bytesReceived.GetValueOrDefault(data.ProcessID) + data.size;
                };

                _session.Source.Kernel.ProcessStart += data =>
                {
                    if (data.ProcessID > 0)
                    {
                        string imageName = data.ImageFileName;
                        _metadataService.RegisterProcessStart(data.ProcessID, data.ParentID, imageName);

                        if (_monitoringStrategy == ProcessMonitoringStrategy.ProcessStartEtw)
                        {
                            if (imageName.Contains("msedgewebview2", StringComparison.OrdinalIgnoreCase))
                            {
                                Task.Run(() => HandleWebView2Spawned(data.ProcessID));
                            }
                        }
                    }
                };

                Task.Run(() =>
                {
                    try { IsRunning = true; _session.Source.Process(); }
                    catch (Exception ex) { _logError($"ETW Loop: {ex.Message}"); }
                    finally { IsRunning = false; }
                });
            }
            catch (Exception ex)
            {
                _logError($"ETW Start: {ex.Message}");
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
                var meta = _metadataService.GetMetadataForPid(pid);
                var isSigned = meta.Signature.Contains("Signed");
                var severity = isSigned ? AlertSeverity.Info : AlertSeverity.Critical;

                string spawnReason = "General Rendering";
                string parentLower = meta.ParentProcessName.ToLower();
                if (parentLower.Contains("searchhost")) spawnReason = "Search UI rendering";
                else if (parentLower.Contains("widgets")) spawnReason = "Widgets content rendering";
                else if (parentLower.Contains("msedge")) spawnReason = "Edge browser sub-process";

                var alert = new AlertEntry
                {
                    Message = $"[Proactive WebView2 Spawned] PID {pid} by {meta.ParentProcessName} (Reason: {spawnReason})\nPath: {meta.ExecutablePath}\nSignature: {meta.Signature}",
                    Severity = severity,
                    Timestamp = DateTime.Now.ToString("HH:mm:ss")
                };

                OnProactiveAlert?.Invoke(alert);
            }
            catch (Exception ex)
            {
                _logError($"Proactive evaluation error for PID {pid}: {ex.Message}");
            }
        }

        public void Stop()
        {
            _session?.Dispose();
            _session = null;
        }

        /// <summary>
        /// Returns aggregate (TotalSent, TotalReceived) across all tracked PIDs.
        /// </summary>
        public (long TotalSent, long TotalReceived) GetTotalTrafficStats()
        {
            lock (_lock)
            {
                long sent = 0, recv = 0;
                foreach (var v in _bytesSent.Values) sent += v;
                foreach (var v in _bytesReceived.Values) recv += v;
                return (sent, recv);
            }
        }

        // ─────────────────────────────────────────────────────────────────────────
        //  P/Invoke: IPv4 TCP table
        // ─────────────────────────────────────────────────────────────────────────

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

        private const int AF_INET  = 2;
        private const int AF_INET6 = 23;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const uint TCP_STATE_ESTABLISHED = 5;
        private const uint TCP_STATE_CLOSE_WAIT  = 8;
        private const uint TCP_STATE_TIME_WAIT   = 11;

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

        // ─────────────────────────────────────────────────────────────────────────
        //  P/Invoke: IPv6 TCP table (Fix #12)
        // ─────────────────────────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucLocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ucRemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public uint dwState;
            public uint dwOwningPid;
        }

        /// <summary>
        /// Converts a network-byte-order port (from the TCP table) to host-byte-order.
        /// </summary>
        private static int NetworkToHostPort(uint rawPort)
        {
            return IPAddress.NetworkToHostOrder((short)(rawPort & 0xFFFF)) & 0xFFFF;
        }

        public List<ConnectionInfo> GetConnections(HashSet<string> ignoredApps, Dictionary<string, BlockedIPMetadata> blockedIPs, HashSet<string> blockedProcessNames)
        {
            var list = new List<ConnectionInfo>();

            EnumerateIPv4Connections(list, ignoredApps, blockedIPs, blockedProcessNames);
            EnumerateIPv6Connections(list, ignoredApps, blockedIPs, blockedProcessNames); // Fix #12

            // Fix #10 (partial): prune stale _connectionStartTimes entries after each full scan
            PruneStaleConnectionTimes(list);

            return list;
        }

        private void EnumerateIPv4Connections(List<ConnectionInfo> list, HashSet<string> ignoredApps,
            Dictionary<string, BlockedIPMetadata> blockedIPs, HashSet<string> blockedProcessNames)
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
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
                        if (remoteIP.StartsWith("127.") || remoteIP == "0.0.0.0") continue;

                        int remotePort = NetworkToHostPort(row.dwRemotePort);
                        int localPort  = NetworkToHostPort(row.dwLocalPort);
                        int pid = (int)row.dwOwningPid;

                        AddConnectionToList(list, pid, remoteIP, remotePort, localPort, ignoredApps, blockedIPs, blockedProcessNames);
                    }
                    catch (Exception ex) { _logError($"GetTcpConnections IPv4 row: {ex.Message}"); }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }

        /// <summary>
        /// Fix #12: Enumerate IPv6 TCP connections to capture modern app traffic (Teams, Edge, etc.)
        /// </summary>
        private void EnumerateIPv6Connections(List<ConnectionInfo> list, HashSet<string> ignoredApps,
            Dictionary<string, BlockedIPMetadata> blockedIPs, HashSet<string> blockedProcessNames)
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
            if (bufferSize <= 0) return;

            IntPtr ptr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(ptr, ref bufferSize, true, AF_INET6, TCP_TABLE_OWNER_PID_ALL) != 0) return;

                int rowCount = Marshal.ReadInt32(ptr);
                IntPtr rowPtr = ptr + 4;

                for (int i = 0; i < rowCount; i++)
                {
                    try
                    {
                        var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                        rowPtr += Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

                        if (row.dwState != TCP_STATE_ESTABLISHED && row.dwState != TCP_STATE_CLOSE_WAIT && row.dwState != TCP_STATE_TIME_WAIT) continue;

                        string remoteIP = new IPAddress(row.ucRemoteAddr).ToString();
                        // Skip loopback and unspecified
                        if (remoteIP == "::1" || remoteIP == "::" || remoteIP.StartsWith("fe80", StringComparison.OrdinalIgnoreCase)) continue;

                        int remotePort = NetworkToHostPort(row.dwRemotePort);
                        int localPort  = NetworkToHostPort(row.dwLocalPort);
                        int pid = (int)row.dwOwningPid;

                        AddConnectionToList(list, pid, remoteIP, remotePort, localPort, ignoredApps, blockedIPs, blockedProcessNames);
                    }
                    catch (Exception ex) { _logError($"GetTcpConnections IPv6 row: {ex.Message}"); }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }

        private void AddConnectionToList(List<ConnectionInfo> list, int pid, string remoteIP,
            int remotePort, int localPort, HashSet<string> ignoredApps,
            Dictionary<string, BlockedIPMetadata> blockedIPs, HashSet<string> blockedProcessNames)
        {
            string appName = "Unknown";
            bool isGhosted = false;
            string socketKey = $"{remoteIP}:{remotePort}-{localPort}";

            try
            {
                if (pid > 0)
                {
                    appName = Process.GetProcessById(pid).ProcessName;
                }
                else
                {
                    appName = "Idle";
                }
            }
            catch { appName = "Unknown"; } // Process died before we could query it

            // If it's Idle or dead, check our history cache
            if ((pid == 0 || appName == "Idle" || appName == "Unknown") && _socketHistory.TryGetValue(socketKey, out var originalName))
            {
                appName = originalName;
                isGhosted = true;
            }
            else if (pid > 0 && appName != "Idle" && appName != "Unknown")
            {
                // Cache valid process names
                _socketHistory[socketKey] = appName;
            }

            if (ignoredApps.Contains(appName.ToLower())) return;

            string key = $"{pid}-{remoteIP}:{remotePort}-{localPort}";
            if (!_connectionStartTimes.ContainsKey(key)) _connectionStartTimes[key] = DateTime.Now;

            long sent = 0, recv = 0;
            lock (_lock)
            {
                sent = _bytesSent.GetValueOrDefault(pid);
                recv = _bytesReceived.GetValueOrDefault(pid);
            }

            bool isBlocked = blockedIPs.ContainsKey(remoteIP) || blockedProcessNames.Contains(appName);

            var geoResult = _geoIpService.GetCachedGeoWithCode(remoteIP);
            var meta = _metadataService.GetMetadataForPid(pid);

            list.Add(new ConnectionInfo
            {
                ApplicationName  = appName,
                IsGhosted        = isGhosted,
                PID              = pid,
                Destination      = remoteIP,
                RemotePort       = remotePort,
                LocalPort        = localPort,
                Location         = geoResult.Display,
                CountryCode      = geoResult.CountryCode,
                Domain           = _geoIpService.GetCachedDomain(remoteIP),
                Duration         = (DateTime.Now - _connectionStartTimes[key]).ToString(@"hh\:mm\:ss"),
                UploadBytes      = sent,
                DownloadBytes    = recv,
                IsBlocked        = isBlocked,
                ParentProcessName= meta.ParentProcessName,
                ExecutablePath   = meta.ExecutablePath,
                Signature        = meta.Signature,
                LastModified     = meta.LastModified,
                Ancestry         = _metadataService.GetProcessAncestry(pid)
            });
        }

        /// <summary>
        /// Fix #10 (prune): Remove _connectionStartTimes entries for connections that are
        /// no longer active, preventing unbounded dictionary growth.
        /// </summary>
        private void PruneStaleConnectionTimes(List<ConnectionInfo> activeConnections)
        {
            var activeKeys = new HashSet<string>(activeConnections.Select(c => c.ConnectionKey));

            // Build the set of keys present in _connectionStartTimes but not in active connections
            var staleKeys = _connectionStartTimes.Keys
                .Where(k => !activeKeys.Contains(k))
                .ToList();

            foreach (var key in staleKeys)
                _connectionStartTimes.Remove(key);

            // Also prune socket history for connections that are truly gone
            var activeSocketKeys = new HashSet<string>(activeConnections.Select(c => $"{c.Destination}:{c.RemotePort}-{c.LocalPort}"));
            var staleSocketKeys = _socketHistory.Keys.Where(k => !activeSocketKeys.Contains(k)).ToList();
            foreach (var key in staleSocketKeys)
                _socketHistory.Remove(key);
        }

        public void ResetConnectionsToIp(string destinationIp)
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
                                _logError($"SetTcpEntry failed for {remoteIP} with error code: {res}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logError($"ResetConnectionsToIp row: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logError($"ResetConnectionsToIp: {ex.Message}");
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public List<AlertEntry> AutoEnforce(List<ConnectionInfo> conns, FirewallService fwService, Dictionary<string, BlockedIPMetadata> blockedIPs, HashSet<string> blockedProcessNames)
        {
            var alerts = new List<AlertEntry>();
            if (blockedProcessNames.Count == 0 && blockedIPs.Count == 0) return alerts;

            // We no longer auto-kill processes by name here to prevent system instability.
            // If a process is in blockedProcessNames, we only block its new IPs.
            foreach (var conn in conns)
            {
                if (!blockedProcessNames.Contains(conn.ApplicationName)) continue;
                if (!IPAddress.TryParse(conn.Destination, out _)) continue;

                bool isNewIp = !blockedIPs.ContainsKey(conn.Destination);
                if (!isNewIp) continue;

                if (fwService.AddBlockRule(conn.Destination, conn.ApplicationName))
                {
                    blockedIPs[conn.Destination] = new BlockedIPMetadata { Application = conn.ApplicationName, Timestamp = DateTime.Now };
                    ResetConnectionsToIp(conn.Destination); // Sever any existing active connections
                    alerts.Add(new AlertEntry
                    {
                        Message  = $"Blocked new connection to {conn.Destination} from {conn.ApplicationName}",
                        Severity = AlertSeverity.Warning
                    });
                }
            }

            return alerts;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            GC.SuppressFinalize(this);
        }
    }
}
