using System;
using System.Runtime.InteropServices;

namespace MyFirewall.Desktop.Services
{
    [ComImport, Guid("98325047-C671-4174-8D81-DEFCD3F03186"), CoClass(typeof(NetFwPolicy2Class))]
    interface INetFwPolicy2
    {
        [DispId(1)] int CurrentProfileTypes { get; }
        [DispId(2)] bool FirewallEnabled { [param: In] set; get; }
        [DispId(3)] object ExcludedInterfaces { [param: In] set; get; }
        [DispId(4)] bool BlockAllInboundTraffic { [param: In] set; get; }
        [DispId(5)] bool NotificationsDisabled { [param: In] set; get; }
        [DispId(6)] bool UnicastResponsesToMulticastBroadcastDisabled { [param: In] set; get; }
        [DispId(7)] INetFwRules Rules { get; }
        [DispId(8)] object ServiceRestriction { get; }
        [DispId(9)] void EnableRuleGroup(int profileTypesBitmask, string group, bool enable);
        [DispId(10)] bool IsRuleGroupEnabled(int profileTypesBitmask, string group);
        [DispId(11)] void RestoreLocalFirewallDefaults();
        [DispId(12)] object DefaultInboundAction { [param: In] set; get; }
        [DispId(13)] object DefaultOutboundAction { [param: In] set; get; }
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
        [DispId(1)] string Name { [param: In] set; get; }
        [DispId(2)] string Description { [param: In] set; get; }
        [DispId(3)] string ApplicationName { [param: In] set; get; }
        [DispId(4)] string serviceName { [param: In] set; get; }
        [DispId(5)] int Protocol { [param: In] set; get; }
        [DispId(6)] string LocalPorts { [param: In] set; get; }
        [DispId(7)] string RemotePorts { [param: In] set; get; }
        [DispId(8)] string LocalAddresses { [param: In] set; get; }
        [DispId(9)] string RemoteAddresses { [param: In] set; get; }
        [DispId(10)] string IcmpTypesAndCodes { [param: In] set; get; }
        [DispId(11)] object Direction { [param: In] set; get; }
        [DispId(12)] object Interfaces { [param: In] set; get; }
        [DispId(13)] string InterfaceTypes { [param: In] set; get; }
        [DispId(14)] bool Enabled { [param: In] set; get; }
        [DispId(15)] string Grouping { [param: In] set; get; }
        [DispId(16)] int Profiles { [param: In] set; get; }
        [DispId(17)] bool EdgeTraversal { [param: In] set; get; }
        [DispId(18)] object Action { [param: In] set; get; }
    }

    [ComImport, Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4")]
    class NetFwRuleClass { }
}
