using System;
using System.Collections.Generic;

namespace MyFirewall.Desktop.Services
{
    public class FirewallService
    {
        private const string FirewallRulePrefix = "TCP-Monitor-Block";
        private const int NET_FW_ACTION_BLOCK = 0;
        private const int NET_FW_RULE_DIR_OUT = 2;
        private const int NET_FW_IP_PROTOCOL_ANY = 256;

        private readonly object _fwLock = new();
        private readonly Action<string> _logError;

        public FirewallService(Action<string> logError)
        {
            _logError = logError;
        }

        private INetFwPolicy2? GetPolicy()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            return type is null ? null : (INetFwPolicy2?)Activator.CreateInstance(type);
        }

        public bool RuleExists(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return false;
                    foreach (INetFwRule r in policy.Rules)
                        if (r.Name.StartsWith(FirewallRulePrefix) && r.RemoteAddresses == ip)
                            return true;
                }
                catch (Exception ex) { _logError($"FirewallService.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        public bool AddBlockRule(string ip, string processName)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (RuleExists(ip)) return false;

            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) { _logError("FirewallService: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                    var rule = (INetFwRule)Activator.CreateInstance(ruleType)!;

                    rule.Name = $"{FirewallRulePrefix}-{processName}-{ip}";
                    rule.Description = $"Auto-blocked by TCP Monitor | application={processName}";
                    rule.Protocol = NET_FW_IP_PROTOCOL_ANY;
                    rule.RemoteAddresses = ip;
                    rule.Direction = NET_FW_RULE_DIR_OUT;
                    rule.Action = NET_FW_ACTION_BLOCK;
                    rule.Enabled = true;
                    rule.Profiles = 0x7FFFFFFF;

                    policy.Rules.Add(rule);
                    return true;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.AddBlockRule({ip}): {ex}");
                    return false;
                }
            }
        }

        public void RemoveBlockRule(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return;

                    var toRemove = new List<string>();
                    foreach (INetFwRule r in policy.Rules)
                        if (r.Name.StartsWith(FirewallRulePrefix) && r.RemoteAddresses == ip)
                            toRemove.Add(r.Name);

                    foreach (var name in toRemove)
                        policy.Rules.Remove(name);
                }
                catch (Exception ex) { _logError($"FirewallService.RemoveBlockRule({ip}): {ex}"); }
            }
        }

        /// <summary>
        /// Returns the number of TCP-Monitor firewall rules currently active.
        /// </summary>
        public int GetRuleCount()
        {
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return 0;
                    int count = 0;
                    foreach (INetFwRule r in policy.Rules)
                        if (r.Name.StartsWith(FirewallRulePrefix)) count++;
                    return count;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.GetRuleCount: {ex.Message}");
                    return 0;
                }
            }
        }

        /// <summary>
        /// Returns all TCP-Monitor firewall rules as (RuleName, IP, Enabled) tuples.
        /// </summary>
        public List<(string Name, string IP, bool Enabled)> GetAllRules()
        {
            var rules = new List<(string, string, bool)>();
            lock (_fwLock)
            {
                try
                {
                    var policy = GetPolicy();
                    if (policy is null) return rules;
                    foreach (INetFwRule r in policy.Rules)
                    {
                        if (r.Name.StartsWith(FirewallRulePrefix))
                            rules.Add((r.Name, r.RemoteAddresses ?? "", r.Enabled));
                    }
                }
                catch (Exception ex) { _logError($"FirewallService.GetAllRules: {ex.Message}"); }
            }
            return rules;
        }
    }
}
