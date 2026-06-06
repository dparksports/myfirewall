using System;
using System.Runtime.InteropServices;

namespace MyFirewall.Desktop.Services
{
    public enum NET_FW_IP_PROTOCOL
    {
        NET_FW_IP_PROTOCOL_TCP = 6,
        NET_FW_IP_PROTOCOL_UDP = 17,
        NET_FW_IP_PROTOCOL_ANY = 256
    }

    public enum NET_FW_RULE_DIRECTION
    {
        NET_FW_RULE_DIR_IN = 1,
        NET_FW_RULE_DIR_OUT = 2
    }

    public enum NET_FW_ACTION
    {
        NET_FW_ACTION_BLOCK = 0,
        NET_FW_ACTION_ALLOW = 1
    }

    [ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), CoClass(typeof(NetFwPolicy2Class))]
    interface INetFwPolicy2
    {
        [DispId(1)] int CurrentProfileTypes { get; }
        [DispId(2)] bool FirewallEnabled { get; set; }
        [DispId(3)] object ExcludedInterfaces { get; set; }
        [DispId(4)] bool BlockAllInboundTraffic { get; set; }
        [DispId(5)] bool NotificationsDisabled { get; set; }
        [DispId(6)] bool UnicastResponsesToMulticastBroadcastDisabled { get; set; }
        [DispId(7)] INetFwRules Rules { get; }
        [DispId(8)] object ServiceRestriction { get; }
        [DispId(9)] void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);
        [DispId(10)] bool IsRuleGroupEnabled(int profileTypesBitmask, string group);
        [DispId(11)] void RestoreLocalFirewallDefaults();
        [DispId(12)] NET_FW_ACTION DefaultInboundAction { get; set; }
        [DispId(13)] NET_FW_ACTION DefaultOutboundAction { get; set; }
        [DispId(14)] bool IsRuleGroupCurrentlyEnabled(string group);
        [DispId(15)] object LocalPolicyModifyState { get; }
    }

    [ComImport, Guid("D46D2478-9AC9-4008-9DC7-5563CE5536CC")]
    class NetFwPolicy2Class { }

    [ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
    interface INetFwRules : System.Collections.IEnumerable
    {
        [DispId(1)] int Count { get; }
        [DispId(2)] void Add(INetFwRule rule);
        [DispId(3)] void Remove(string name);
        [DispId(4)] INetFwRule Item(string name);
    }

    [ComImport, Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2"), CoClass(typeof(NetFwRuleClass))]
    interface INetFwRule
    {
        [DispId(1)] string Name { get; set; }
        [DispId(2)] string Description { get; set; }
        [DispId(3)] string ApplicationName { get; set; }
        [DispId(4)] string serviceName { get; set; }
        [DispId(5)] int Protocol { get; set; }
        [DispId(6)] string LocalPorts { get; set; }
        [DispId(7)] string RemotePorts { get; set; }
        [DispId(8)] string LocalAddresses { get; set; }
        [DispId(9)] string RemoteAddresses { get; set; }
        [DispId(10)] string IcmpTypesAndCodes { get; set; }
        [DispId(11)] NET_FW_RULE_DIRECTION Direction { get; set; }
        [DispId(12)] object Interfaces { get; set; }
        [DispId(13)] string InterfaceTypes { get; set; }
        [DispId(14)] bool Enabled { get; set; }
        [DispId(15)] string Grouping { get; set; }
        [DispId(16)] int Profiles { get; set; }
        [DispId(17)] bool EdgeTraversal { get; set; }
        [DispId(18)] NET_FW_ACTION Action { get; set; }
    }

    [ComImport, Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
    class NetFwRuleClass { }
}

