using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MyFirewall.Desktop.Models;

namespace MyFirewall.Desktop.Services
{
    public class DataService
    {
        private readonly string _blockedFile;
        private readonly string _ignoredFile;
        private readonly string _crashLogFile;
        private readonly Action<string> _logError;

        public DataService(Action<string> logError)
        {
            _logError = logError;

            // Point to the parent directory where the console app's files reside
            // AppDomain.CurrentDomain.BaseDirectory is usually bin/Debug/net8.0-windows/
            string baseDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            _blockedFile = Path.Combine(baseDir, "blocked.txt");
            _ignoredFile = Path.Combine(baseDir, "ignored.txt");
            _crashLogFile = Path.Combine(baseDir, "crash.log");
        }

        public (Dictionary<string, BlockedIPMetadata> BlockedIPs, HashSet<string> IgnoredApps) LoadData()
        {
            var blocked = new Dictionary<string, BlockedIPMetadata>();
            var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                if (File.Exists(_ignoredFile))
                {
                    var lines = File.ReadAllLines(_ignoredFile)
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Select(x => x.Trim().ToLower());
                    foreach (var line in lines) ignored.Add(line);
                }

                if (File.Exists(_blockedFile))
                {
                    foreach (var line in File.ReadAllLines(_blockedFile))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = line.Split('|');
                        string ip = parts[0].Trim();
                        if (IPAddress.TryParse(ip, out _))
                        {
                            string app = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                            DateTime timestamp = DateTime.Now;
                            if (parts.Length >= 3 && DateTime.TryParse(parts[2].Trim(), out var dt))
                            {
                                timestamp = dt;
                            }
                            blocked[ip] = new BlockedIPMetadata { Application = app, Timestamp = timestamp };
                        }
                    }
                }
            }
            catch (Exception ex) { _logError($"LoadData: {ex.Message}"); }

            return (blocked, ignored);
        }

        public void SaveIgnored(IEnumerable<string> ignoredApps)
        {
            try { File.WriteAllLines(_ignoredFile, ignoredApps); }
            catch (Exception ex) { _logError($"SaveIgnoreList: {ex.Message}"); }
        }

        public void SaveBlocked(Dictionary<string, BlockedIPMetadata> blockedIPs)
        {
            try { File.WriteAllLines(_blockedFile, blockedIPs.Select(kvp => $"{kvp.Key}|{kvp.Value.Application}|{kvp.Value.Timestamp:O}")); }
            catch (Exception ex) { _logError($"SaveBlockList: {ex.Message}"); }
        }

        /// <summary>
        /// Export a full report of blocked IPs and recent alerts to a timestamped file.
        /// Returns the path to the exported file.
        /// </summary>
        public string ExportReport(Dictionary<string, BlockedIPMetadata> blockedIPs, IEnumerable<string> ignoredApps, IEnumerable<string> alerts)
        {
            string baseDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            string fileName = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            string filePath = Path.Combine(baseDir, fileName);

            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("═══════════════════════════════════════════════════════");
                sb.AppendLine("  TCP Monitor — Security Report");
                sb.AppendLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine("═══════════════════════════════════════════════════════");
                sb.AppendLine();

                sb.AppendLine($"  Blocked IPs ({blockedIPs.Count}):");
                sb.AppendLine("  ─────────────────────────────────────────────────────");
                foreach (var kvp in blockedIPs.OrderBy(x => x.Key))
                    sb.AppendLine($"    {kvp.Key,-20} │ {kvp.Value.Application,-25} │ {kvp.Value.Timestamp:yyyy-MM-dd HH:mm:ss}");
                if (blockedIPs.Count == 0) sb.AppendLine("    (none)");
                sb.AppendLine();

                sb.AppendLine($"  Ignored Applications:");
                sb.AppendLine("  ─────────────────────────────────────────────────────");
                foreach (var app in ignoredApps.OrderBy(x => x))
                    sb.AppendLine($"    {app}");
                sb.AppendLine();

                sb.AppendLine($"  Recent Alerts:");
                sb.AppendLine("  ─────────────────────────────────────────────────────");
                foreach (var alert in alerts)
                    sb.AppendLine($"    {alert}");
                sb.AppendLine();

                sb.AppendLine("═══════════════════════════════════════════════════════");

                File.WriteAllText(filePath, sb.ToString());
                return filePath;
            }
            catch (Exception ex)
            {
                _logError($"ExportReport: {ex.Message}");
                return "";
            }
        }
    }
}
