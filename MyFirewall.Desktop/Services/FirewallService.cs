using System;
using System.Collections.Generic;

namespace MyFirewall.Desktop.Services
{
    /// <summary>
    /// Manages Windows Firewall rules via the HNetCfg.FwPolicy2 COM API.
    /// Uses dynamic dispatch for all COM calls to avoid .NET 8 vtable marshalling regressions.
    /// Fix #5: RuleExists check is inlined inside AddBlockRule's lock to prevent TOCTOU races.
    /// Fix #7: FirewallRuleCount is cached and only re-queried when rules change.
    /// Fix #A: Removed duplicate constant definitions; use ComInterop.cs enums throughout.
    /// </summary>
    public class FirewallService
    {
        private const string FirewallRulePrefix = "TCP-Monitor-Block";

        private readonly object _fwLock = new();
        private readonly Action<string> _logError;

        // Fix #7: Cached rule count — avoids enumerating all WFP rules every 2 seconds.
        private int _cachedRuleCount = -1;

        public FirewallService(Action<string> logError)
        {
            _logError = logError;
        }

        private dynamic? GetPolicy()
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            return type is null ? null : Activator.CreateInstance(type);
        }

        /// <summary>
        /// Fix #5: Private non-locking variant used only inside an existing lock scope.
        /// Callers must hold _fwLock before calling this.
        /// </summary>
        private bool RuleExistsUnsafe(dynamic policy, string ip)
        {
            try
            {
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
            catch (Exception ex) { _logError($"FirewallService.RuleExistsUnsafe: {ex.Message}"); }
            return false;
        }

        /// <summary>
        /// Public rule-existence check (acquires its own lock).
        /// </summary>
        public bool RuleExists(string ip)
        {
            lock (_fwLock)
            {
                try
                {
                    dynamic? policy = GetPolicy();
                    if (policy is null) return false;
                    return RuleExistsUnsafe(policy, ip);
                }
                catch (Exception ex) { _logError($"FirewallService.RuleExists: {ex.Message}"); }
                return false;
            }
        }

        public bool AddBlockRule(string ip, string processName)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;

            lock (_fwLock)
            {
                try
                {
                    dynamic? policy = GetPolicy();
                    if (policy is null) { _logError("FirewallService: Could not acquire HNetCfg.FwPolicy2"); return false; }

                    // Fix #5: Check existence inside the lock — no window between check and add.
                    if (RuleExistsUnsafe(policy, ip)) return true;

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

                    // Fix #7: Invalidate cache after a successful add.
                    _cachedRuleCount = -1;
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

                    // Fix #7: Invalidate cache after removal.
                    if (toRemove.Count > 0) _cachedRuleCount = -1;
                }
                catch (Exception ex) { _logError($"FirewallService.RemoveBlockRule({ip}): {ex.Message}"); }
            }
        }

        /// <summary>
        /// Fix #7: Returns a cached count of TCP-Monitor firewall rules.
        /// Only enumerates when invalidated by Add/Remove (avoids expensive COM enumeration every 2s).
        /// </summary>
        public int GetRuleCount()
        {
            lock (_fwLock)
            {
                if (_cachedRuleCount >= 0) return _cachedRuleCount;

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
                    _cachedRuleCount = count;
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
