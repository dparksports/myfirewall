using System;
using System.Diagnostics;

namespace MyFirewall.Desktop.Services
{
    public class SystemSettingsService
    {
        private readonly Action<string> _logError;

        public SystemSettingsService(Action<string> logError)
        {
            _logError = logError;
        }

        public bool IsLanguageSyncEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\SettingSync");
                if (key != null)
                {
                    var val = key.GetValue("DisableLanguageSettingSync");
                    if (val is int i && i == 1) return false;
                }
                return true;
            }
            catch { return true; }
        }

        public void SetLanguageSyncEnabled(bool enable)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Policies\Microsoft\Windows\SettingSync");
                key.SetValue("DisableLanguageSettingSync", enable ? 0 : 1, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch (Exception ex) { _logError($"SetLanguageSyncEnabled: {ex.Message}"); }
        }

        public bool IsWidgetsEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Dsh");
                if (key != null)
                {
                    var val = key.GetValue("AllowNewsAndInterests");
                    if (val is int i && i == 0) return false;
                }
                return true;
            }
            catch { return true; }
        }

        public void SetWidgetsEnabled(bool enable)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Dsh");
                key.SetValue("AllowNewsAndInterests", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                
                if (!enable)
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = "-Command \"Get-AppxPackage *WebExperience* | Remove-AppxPackage\"",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    Process.Start(psi);
                }
            }
            catch (Exception ex) { _logError($"SetWidgetsEnabled: {ex.Message}"); }
        }

        public bool IsSearchHostEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
                if (key != null)
                {
                    var val = key.GetValue("SearchboxTaskbarMode");
                    if (val is int i && i == 0) return false;
                }
                return true; // Default is true (enabled)
            }
            catch { return true; }
        }

        public void SetSearchHostEnabled(bool enable)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Search");
                key.SetValue("SearchboxTaskbarMode", enable ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch (Exception ex) { _logError($"SetSearchHostEnabled: {ex.Message}"); }
        }

        public void StopProcess(string processName)
        {
            try
            {
                var processes = Process.GetProcessesByName(processName);
                foreach (var p in processes)
                {
                    p.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex)
            {
                _logError($"Failed to stop {processName}: {ex.Message}");
            }
        }
    }
}
