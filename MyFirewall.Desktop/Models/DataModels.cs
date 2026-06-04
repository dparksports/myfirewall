using System;
using System.Windows.Media;

namespace MyFirewall.Desktop.Models
{
    public enum AlertSeverity
    {
        Info,
        Warning,
        Critical
    }

    public class AlertEntry
    {
        public string Message { get; set; } = "";
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public AlertSeverity Severity { get; set; } = AlertSeverity.Warning;

        public SolidColorBrush AlertColor => Severity switch
        {
            AlertSeverity.Info => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#58A6FF")),
            AlertSeverity.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D29922")),
            AlertSeverity.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F85149")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8B949E"))
        };

        public string AlertIcon => Severity switch
        {
            AlertSeverity.Info => "ℹ",
            AlertSeverity.Warning => "⚠",
            AlertSeverity.Critical => "🛑",
            _ => "•"
        };

        public SolidColorBrush AlertBgColor => Severity switch
        {
            AlertSeverity.Info => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#0D2137")),
            AlertSeverity.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2A2316")),
            AlertSeverity.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2A1616")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#161B22"))
        };

        public SolidColorBrush AlertBorderColor => Severity switch
        {
            AlertSeverity.Info => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1F4068")),
            AlertSeverity.Warning => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5C4B1F")),
            AlertSeverity.Critical => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#5C1F1F")),
            _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#30363D"))
        };
    }

    public class BlockedIPMetadata
    {
        public string Application { get; set; } = "Unknown";
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    public class BlockedIPEntry
    {
        public string IP { get; set; } = "";
        public string Application { get; set; } = "";
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string DisplayTimestamp => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    }

    public class IgnoredAppEntry
    {
        public string Application { get; set; } = "";
    }
}
