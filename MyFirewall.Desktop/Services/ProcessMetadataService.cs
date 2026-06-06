using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using MyFirewall.Desktop.Models;

namespace MyFirewall.Desktop.Services
{
    public class ProcessMetadata
    {
        public string ParentProcessName { get; set; } = "Unknown";
        public int ParentPID { get; set; }
        public string ExecutablePath { get; set; } = "N/A";
        public string Signature { get; set; } = "Unsigned / Unknown";
        public string LastModified { get; set; } = "N/A";
    }

    public class ProcessMetadataService
    {
        // Fix #9: TTL-based cache eviction (60s) — Windows recycles PIDs, so a long-lived
        // cache could associate old metadata with a new process that reuses the same PID.
        private readonly struct CacheEntry
        {
            public readonly ProcessMetadata Metadata;
            public readonly DateTime Expires;
            public CacheEntry(ProcessMetadata m, DateTime expires) { Metadata = m; Expires = expires; }
            public bool IsValid => DateTime.Now < Expires;
        }

        private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);
        private readonly ConcurrentDictionary<int, CacheEntry> _cache = new();

        // ETW Process History Cache
        private readonly ConcurrentDictionary<int, ProcessHistoryNode> _processHistory = new();
        private const int MaxHistoryNodes = 50000;
        
        public void RegisterProcessStart(int pid, int parentPid, string processName)
        {
            if (_processHistory.Count >= MaxHistoryNodes)
            {
                // Prune oldest 10%
                var oldestKeys = _processHistory.OrderBy(x => x.Value.StartTime).Take(MaxHistoryNodes / 10).Select(x => x.Key).ToList();
                foreach (var key in oldestKeys) _processHistory.TryRemove(key, out _);
            }

            _processHistory[pid] = new ProcessHistoryNode
            {
                PID = pid,
                ParentPID = parentPid,
                ProcessName = processName,
                StartTime = DateTime.Now
            };
        }

        public List<ProcessHistoryNode> GetProcessAncestry(int pid)
        {
            var ancestry = new List<ProcessHistoryNode>();
            var visited = new HashSet<int>();

            int currentPid = pid;

            while (currentPid > 0 && visited.Add(currentPid))
            {
                if (_processHistory.TryGetValue(currentPid, out var node))
                {
                    ancestry.Add(node);
                    currentPid = node.ParentPID;
                }
                else
                {
                    // Fallback to active process query if not in ETW history
                    try
                    {
                        var pbi = new PROCESS_BASIC_INFORMATION();
                        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, currentPid);
                        if (hProcess != IntPtr.Zero)
                        {
                            int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                            CloseHandle(hProcess);
                            if (status == 0)
                            {
                                int parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
                                
                                string pName = "Unknown";
                                try { pName = Process.GetProcessById(currentPid).ProcessName; } catch { }

                                var fallbackNode = new ProcessHistoryNode
                                {
                                    PID = currentPid,
                                    ParentPID = parentPid,
                                    ProcessName = pName,
                                    StartTime = DateTime.MinValue // Unknown start time
                                };
                                ancestry.Add(fallbackNode);
                                currentPid = parentPid;
                                continue;
                            }
                        }
                    }
                    catch { }

                    break; // Could not find parent
                }
            }

            // Reverse to get root -> child order
            ancestry.Reverse();
            return ancestry;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, [Out] StringBuilder lpExeName, ref int lpdwSize);

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

        public ProcessMetadata GetMetadataForPid(int pid)
        {
            if (pid <= 0) return new ProcessMetadata();

            // Return cached entry if still within TTL
            if (_cache.TryGetValue(pid, out var entry) && entry.IsValid)
                return entry.Metadata;

            // Expired or missing — resolve fresh and store with new TTL
            var metadata = ResolveMetadata(pid);
            _cache[pid] = new CacheEntry(metadata, DateTime.Now.Add(CacheTtl));
            return metadata;
        }

        private ProcessMetadata ResolveMetadata(int pid)
        {
            var meta = new ProcessMetadata();
            IntPtr hProcess = IntPtr.Zero;

            try
            {
                // Try opening with limited and full query rights
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                }

                if (hProcess != IntPtr.Zero)
                {
                    // 1. Resolve Executable Path
                    var sb = new StringBuilder(1024);
                    int size = sb.Capacity;
                    if (QueryFullProcessImageName(hProcess, 0, sb, ref size))
                    {
                        meta.ExecutablePath = sb.ToString();
                    }

                    // 2. Resolve Parent PID
                    var pbi = new PROCESS_BASIC_INFORMATION();
                    int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out _);
                    if (status == 0)
                    {
                        meta.ParentPID = pbi.InheritedFromUniqueProcessId.ToInt32();
                        if (meta.ParentPID > 0)
                        {
                            try
                            {
                                using var parent = Process.GetProcessById(meta.ParentPID);
                                meta.ParentProcessName = $"{parent.ProcessName} (PID {meta.ParentPID})";
                            }
                            catch
                            {
                                meta.ParentProcessName = $"PID {meta.ParentPID} (Exited)";
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fallback to standard diagnostics process resolution if handle query fails
                try
                {
                    using var process = Process.GetProcessById(pid);
                    meta.ExecutablePath = process.MainModule?.FileName ?? "N/A";
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

            // Fill in File specific properties if path was successfully resolved
            if (!string.IsNullOrEmpty(meta.ExecutablePath) && meta.ExecutablePath != "N/A" && File.Exists(meta.ExecutablePath))
            {
                try
                {
                    var fileInfo = new FileInfo(meta.ExecutablePath);
                    meta.LastModified = fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss");
                    meta.Signature = GetDigitalSignature(meta.ExecutablePath);
                }
                catch
                {
                    meta.LastModified = "Error reading details";
                    meta.Signature = "Unsigned / Unknown";
                }
            }

            return meta;
        }

        private static string GetDigitalSignature(string filePath)
        {
            try
            {
                using (var cert = X509Certificate.CreateFromSignedFile(filePath))
                {
                    using (var cert2 = new X509Certificate2(cert))
                    {
                        // Clean up Subject string for cleaner representation
                        string subject = cert2.Subject;
                        if (subject.Contains("CN="))
                        {
                            int start = subject.IndexOf("CN=") + 3;
                            int end = subject.IndexOf(',', start);
                            if (end > start)
                            {
                                return "Signed by: " + subject.Substring(start, end - start);
                            }
                            return "Signed by: " + subject.Substring(start);
                        }
                        return "Signed: " + cert2.Subject;
                    }
                }
            }
            catch
            {
                return "Unsigned";
            }
        }
    }
}
