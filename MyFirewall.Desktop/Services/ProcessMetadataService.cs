using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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
        private readonly ConcurrentDictionary<int, ProcessMetadata> _cache = new();

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

            if (_cache.TryGetValue(pid, out var cached))
                return cached;

            var metadata = ResolveMetadata(pid);
            _cache[pid] = metadata;
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
