using System;

namespace MyFirewall.Desktop.Models
{
    public class ConnectionInfo
    {
        public string ApplicationName { get; set; } = "";
        public int PID { get; set; }
        public string Destination { get; set; } = "";
        public string Location { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Duration { get; set; } = "";
        public long UploadBytes { get; set; }
        public long DownloadBytes { get; set; }
        public bool IsBlocked { get; set; }
        
        public string Upload => FormatBytes(UploadBytes);
        public string Download => FormatBytes(DownloadBytes);

        public string StatusColor => IsBlocked ? "#F85149" : "#3FB950"; // Red or Green
        
        // Formats bytes into a human-readable string (KB, MB)
        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }
    }
}
