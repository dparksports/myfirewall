using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace MyFirewall.Desktop.Services
{
    public class DataService
    {
        private const string BlockedFile = "blocked.txt";
        private const string IgnoredFile = "ignored.txt";
        private readonly Action<string> _logError;

        public DataService(Action<string> logError)
        {
            _logError = logError;
        }

        public (Dictionary<string, string> BlockedIPs, HashSet<string> IgnoredApps) LoadData()
        {
            var blocked = new Dictionary<string, string>();
            var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                if (File.Exists(IgnoredFile))
                {
                    var lines = File.ReadAllLines(IgnoredFile)
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Select(x => x.Trim().ToLower());
                    foreach (var line in lines) ignored.Add(line);
                }

                if (File.Exists(BlockedFile))
                {
                    foreach (var line in File.ReadAllLines(BlockedFile))
                    {
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        var parts = line.Split('|');
                        string ip = parts[0].Trim();
                        if (IPAddress.TryParse(ip, out _))
                            blocked[ip] = parts.Length >= 2 ? parts[1].Trim() : "Unknown";
                    }
                }
            }
            catch (Exception ex) { _logError($"LoadData: {ex.Message}"); }

            return (blocked, ignored);
        }

        public void SaveIgnored(IEnumerable<string> ignoredApps)
        {
            try { File.WriteAllLines(IgnoredFile, ignoredApps); }
            catch (Exception ex) { _logError($"SaveIgnoreList: {ex.Message}"); }
        }

        public void SaveBlocked(Dictionary<string, string> blockedIPs)
        {
            try { File.WriteAllLines(BlockedFile, blockedIPs.Select(kvp => $"{kvp.Key}|{kvp.Value}")); }
            catch (Exception ex) { _logError($"SaveBlockList: {ex.Message}"); }
        }
    }
}
