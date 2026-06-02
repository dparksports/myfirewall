using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    public class NetworkMonitorService : IDisposable
    {
        private static readonly string SessionName = KernelTraceEventParser.KernelSessionName;
        private TraceEventSession? _session;
        private readonly Dictionary<int, long> _bytesSent = new();
        private readonly Dictionary<int, long> _bytesReceived = new();
        private readonly object _lock = new();
        private readonly Action<string> _logError;
        private readonly GeoIpService _geoIpService;
        private bool _disposed;

        private readonly Dictionary<string, DateTime> _connectionStartTimes = new();
        public bool IsRunning { get; private set; }

        public NetworkMonitorService(Action<string> logError, GeoIpService geoIpService)
        {
            _logError = logError;
            _geoIpService = geoIpService;
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

                _session = new TraceEventSession(SessionName) { StopOnDispose = true };
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);

                _session.Source.Kernel.TcpIpSend += data =>
                {
                    lock (_lock) _bytesSent[data.ProcessID] = _bytesSent.GetValueOrDefault(data.ProcessID) + data.size;
                };
                _session.Source.Kernel.TcpIpRecv += data =>
                {
                    lock (_lock) _bytesReceived[data.ProcessID] = _bytesReceived.GetValueOrDefault(data.ProcessID) + data.size;
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

        public void Stop() => Dispose();

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

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

        private const int AF_INET = 2;
        private const int TCP_TABLE_OWNER_PID_ALL = 5;
        private const uint TCP_STATE_ESTABLISHED = 5;

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

        /// <summary>
        /// Converts a network-byte-order port (from the TCP table) to host-byte-order.
        /// </summary>
        private static int NetworkToHostPort(uint rawPort)
        {
            return IPAddress.NetworkToHostOrder((short)(rawPort & 0xFFFF)) & 0xFFFF;
        }

        public List<ConnectionInfo> GetConnections(HashSet<string> ignoredApps, Dictionary<string, string> blockedIPs, HashSet<string> blockedProcessNames)
        {
            var list = new List<ConnectionInfo>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL);
            IntPtr ptr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                if (GetExtendedTcpTable(ptr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                    return list;

                int rowCount = Marshal.ReadInt32(ptr);
                IntPtr rowPtr = ptr + 4;

                for (int i = 0; i < rowCount; i++)
                {
                    try
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                        if (row.dwState != TCP_STATE_ESTABLISHED) continue;

                        string remoteIP = new IPAddress(BitConverter.GetBytes(row.dwRemoteAddr)).ToString();
                        if (remoteIP.StartsWith("127.") || remoteIP == "0.0.0.0") continue;

                        int pid = (int)row.dwOwningPid;
                        string appName = "Unknown";
                        try
                        {
                            appName = Process.GetProcessById(pid).ProcessName;
                            if (ignoredApps.Contains(appName.ToLower())) continue;
                        }
                        catch { continue; }

                        string key = $"{pid}-{remoteIP}";
                        if (!_connectionStartTimes.ContainsKey(key)) _connectionStartTimes[key] = DateTime.Now;

                        long sent = 0, recv = 0;
                        lock (_lock)
                        {
                            sent = _bytesSent.GetValueOrDefault(pid);
                            recv = _bytesReceived.GetValueOrDefault(pid);
                        }

                        bool isBlocked = blockedIPs.ContainsKey(remoteIP) || blockedProcessNames.Contains(appName);

                        int remotePort = NetworkToHostPort(row.dwRemotePort);
                        int localPort = NetworkToHostPort(row.dwLocalPort);

                        // Get geo info with country code
                        var geoResult = _geoIpService.GetCachedGeoWithCode(remoteIP);

                        list.Add(new ConnectionInfo
                        {
                            ApplicationName = appName,
                            PID = pid,
                            Destination = remoteIP,
                            RemotePort = remotePort,
                            LocalPort = localPort,
                            Location = geoResult.Display,
                            CountryCode = geoResult.CountryCode,
                            Domain = _geoIpService.GetCachedDomain(remoteIP),
                            Duration = (DateTime.Now - _connectionStartTimes[key]).ToString(@"hh\:mm\:ss"),
                            UploadBytes = sent,
                            DownloadBytes = recv,
                            IsBlocked = isBlocked
                        });
                    }
                    catch (Exception ex) { _logError($"GetTcpConnections row: {ex.Message}"); }
                }
            }
            finally { Marshal.FreeHGlobal(ptr); }

            return list;
        }

        public List<AlertEntry> AutoEnforce(List<ConnectionInfo> conns, FirewallService fwService, Dictionary<string, string> blockedIPs, HashSet<string> blockedProcessNames)
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
                    blockedIPs[conn.Destination] = conn.ApplicationName;
                    alerts.Add(new AlertEntry
                    {
                        Message = $"Blocked new connection to {conn.Destination} from {conn.ApplicationName}",
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
            _session?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
