using System;
using System.Windows.Media;

namespace MyFirewall.Desktop.Models
{
    public class ConnectionInfo
    {
        private static readonly SolidColorBrush BlockedBrush;
        private static readonly SolidColorBrush AllowedBrush;

        static ConnectionInfo()
        {
            BlockedBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F85149"));
            BlockedBrush.Freeze(); // Thread-safe: frozen brushes can be shared across threads
            AllowedBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#3FB950"));
            AllowedBrush.Freeze();
        }

        public string ApplicationName { get; set; } = "";
        public int PID { get; set; }
        public string Destination { get; set; } = "";
        public int RemotePort { get; set; }
        public int LocalPort { get; set; }
        public string Location { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Duration { get; set; } = "";
        public long UploadBytes { get; set; }
        public long DownloadBytes { get; set; }
        public bool IsBlocked { get; set; }
        public string CountryCode { get; set; } = "";

        // New process metadata fields
        public string ParentProcessName { get; set; } = "Unknown";
        public string ExecutablePath { get; set; } = "N/A";
        public string Signature { get; set; } = "Unsigned / Unknown";
        public string LastModified { get; set; } = "N/A";

        public string Upload => FormatBytes(UploadBytes);
        public string Download => FormatBytes(DownloadBytes);

        public string PortDisplay => RemotePort > 0 ? $":{RemotePort}" : "";

        /// <summary>
        /// Returns a SolidColorBrush for proper WPF binding instead of a string.
        /// </summary>
        public SolidColorBrush StatusBrush => IsBlocked ? BlockedBrush : AllowedBrush;

        // Keep the string version for backward compat with any existing bindings
        public string StatusColor => IsBlocked ? "#F85149" : "#3FB950";

        /// <summary>
        /// Converts a 2-letter country code (e.g. "US") to its flag emoji (🇺🇸).
        /// </summary>
        public string CountryFlag
        {
            get
            {
                if (string.IsNullOrEmpty(CountryCode) || CountryCode.Length != 2) return "🌐";
                try
                {
                    string upper = CountryCode.ToUpperInvariant();
                    // Each letter maps to a Regional Indicator Symbol (U+1F1E6 + offset)
                    int first = 0x1F1E6 + (upper[0] - 'A');
                    int second = 0x1F1E6 + (upper[1] - 'A');
                    return char.ConvertFromUtf32(first) + char.ConvertFromUtf32(second);
                }
                catch { return "🌐"; }
            }
        }

        /// <summary>
        /// Unique key for smart-diff comparison (PID + IP + Ports identifies a unique connection).
        /// </summary>
        public string ConnectionKey => $"{PID}-{Destination}-{LocalPort}-{RemotePort}";

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
