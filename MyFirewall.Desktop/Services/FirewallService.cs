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

        private dynamic? GetPolicy()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            return type is null ? null : Activator.CreateInstance(type);
        }

        public bool RuleExists(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    dynamic? policy = GetPolicy();
                    if (policy is null) return false;
                    
                    // Use dynamic to avoid vtable-based COM marshalling which causes memory corruption
                    foreach (dynamic r in (dynamic)policy.Rules)
                    {
                        try
                        {
                            if (((string)r.Name).StartsWith(FirewallRulePrefix) && (string)r.RemoteAddresses == ip)
                                return true;
                        }
                        catch { /* skip rules we can't read */ }
                    }
                }
                catch (Exception ex) { _logError($"FirewallService.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        public bool AddBlockRule(string ip, string processName)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            if (RuleExists(ip)) return true;

            lock (_fwLock)
            {
                try
                {
                    dynamic? policy = GetPolicy();
                    if (policy is null) { _logError("FirewallService: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                    
                    // Fix for AccessViolationException/E_INVALIDARG: Use dynamic for EVERYTHING.
                    // .NET 8 has a regression where vtable-based COM marshalling for INetFwRule
                    // causes memory corruption and E_INVALIDARG when adding rules.
                    dynamic rule = Activator.CreateInstance(ruleType)!;

                    rule.Name = $"{FirewallRulePrefix}-{processName}-{ip}";
                    rule.Description = $"Auto-blocked by TCP Monitor | application={processName}";
                    rule.Protocol = (int)NET_FW_IP_PROTOCOL.NET_FW_IP_PROTOCOL_ANY;
                    rule.RemoteAddresses = ip;
                    rule.Direction = (int)NET_FW_RULE_DIRECTION.NET_FW_RULE_DIR_OUT;
                    rule.Action = (int)NET_FW_ACTION.NET_FW_ACTION_BLOCK;
                    rule.Enabled = true;
                    rule.Profiles = 7; // All profiles

                    ((dynamic)policy.Rules).Add(rule); // No cast to INetFwRule
                    return true;
                }
                catch (Exception ex)
                {
                    _logError($"FirewallService.AddBlockRule({ip}): {ex.Message}");
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
                    dynamic? policy = GetPolicy();
                    if (policy is null) return;

                    var toRemove = new List<string>();
                    foreach (dynamic r in (dynamic)policy.Rules)
                    {
                        try
                        {
                            if (((string)r.Name).StartsWith(FirewallRulePrefix) && (string)r.RemoteAddresses == ip)
                                toRemove.Add((string)r.Name);
                        }
                        catch { }
                    }

                    foreach (var name in toRemove)
                        ((dynamic)policy.Rules).Remove(name);
                }
                catch (Exception ex) { _logError($"FirewallService.RemoveBlockRule({ip}): {ex.Message}"); }
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
                    dynamic? policy = GetPolicy();
                    if (policy is null) return 0;
                    int count = 0;
                    foreach (dynamic r in (dynamic)policy.Rules)
                    {
                        try
                        {
                            if (((string)r.Name).StartsWith(FirewallRulePrefix)) count++;
                        }
                        catch { }
                    }
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
                    dynamic? policy = GetPolicy();
                    if (policy is null) return rules;
                    foreach (dynamic r in (dynamic)policy.Rules)
                    {
                        try
                        {
                            if (((string)r.Name).StartsWith(FirewallRulePrefix))
                                rules.Add(((string)r.Name, (string)r.RemoteAddresses ?? "", (bool)r.Enabled));
                        }
                        catch { }
                    }
                }
                catch (Exception ex) { _logError($"FirewallService.GetAllRules: {ex.Message}"); }
            }
            return rules;
        }
    }
}
