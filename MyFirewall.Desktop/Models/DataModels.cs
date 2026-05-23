using System;

namespace MyFirewall.Desktop.Models
{
    public class AlertEntry
    {
        public string Message { get; set; } = "";
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss");
    }

    public class BlockedIPEntry
    {
        public string IP { get; set; } = "";
        public string Application { get; set; } = "";
    }

    public class IgnoredAppEntry
    {
        public string Application { get; set; } = "";
    }
}
