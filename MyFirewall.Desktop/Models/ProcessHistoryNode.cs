using System;

namespace MyFirewall.Desktop.Models
{
    public class ProcessHistoryNode
    {
        public int PID { get; set; }
        public int ParentPID { get; set; }
        public string ProcessName { get; set; } = "Unknown";
        public DateTime StartTime { get; set; }
    }
}
