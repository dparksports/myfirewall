using System;
using System.IO;

namespace TestFw
{
    class Program3
    {
        static void Main(string[] args)
        {
            string logPath = @"C:\users\j3b650v2\myfirewall\test_fw3.log";
            File.WriteAllText(logPath, "Starting C# test 3...\n");

            try
            {
                var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
                dynamic policy = Activator.CreateInstance(type)!;

                var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
                dynamic rule = Activator.CreateInstance(ruleType)!;
                
                rule.Name = "Test-Fw-Csharp3-Pipe";
                // Intentionally use a pipe to see if it causes E_INVALIDARG upon Add()
                rule.Description = "Test | Pipe";
                rule.Protocol = 6;
                rule.RemoteAddresses = "23.217.118.213";
                rule.Direction = 2;
                rule.Action = 0;
                rule.Enabled = true;

                try
                {
                    policy.Rules.Add(rule);
                    File.AppendAllText(logPath, "Rule ADDED!\n");
                    policy.Rules.Remove(rule.Name);
                }
                catch (Exception e)
                {
                    File.AppendAllText(logPath, $"Add failed: {e.Message}\n");
                }
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"Global exception: {ex.Message}\n");
            }
        }
    }
}
