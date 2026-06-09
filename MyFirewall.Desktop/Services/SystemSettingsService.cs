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

        public bool IsStartMenuExperienceHostEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe");
                if (key != null)
                {
                    var val = key.GetValue("Debugger");
                    if (val != null) return false;
                }
                return true;
            }
            catch { return true; }
        }

        public void SetStartMenuExperienceHostEnabled(bool enable)
        {
            try
            {
                if (enable)
                {
                    using var parentKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", writable: true);
                    if (parentKey != null)
                    {
                        parentKey.DeleteSubKeyTree("StartMenuExperienceHost.exe", throwOnMissingSubKey: false);
                    }
                }
                else
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe");
                    key.SetValue("Debugger", "systray.exe", Microsoft.Win32.RegistryValueKind.String);
                }
            }
            catch (Exception ex) { _logError($"SetStartMenuExperienceHostEnabled: {ex.Message}"); }
        }

        public bool IsShellExperienceHostEnabled()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe");
                if (key != null)
                {
                    var val = key.GetValue("Debugger");
                    if (val != null) return false;
                }
                return true;
            }
            catch { return true; }
        }

        public void SetShellExperienceHostEnabled(bool enable)
        {
            try
            {
                if (enable)
                {
                    using var parentKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", writable: true);
                    if (parentKey != null)
                    {
                        parentKey.DeleteSubKeyTree("ShellExperienceHost.exe", throwOnMissingSubKey: false);
                    }
                }
                else
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ShellExperienceHost.exe");
                    key.SetValue("Debugger", "systray.exe", Microsoft.Win32.RegistryValueKind.String);
                }
            }
            catch (Exception ex) { _logError($"SetShellExperienceHostEnabled: {ex.Message}"); }
        }

        public string FindWebView2Path()
        {
            try
            {
                string baseDir = @"C:\Program Files (x86)\Microsoft\EdgeWebView\Application";
                if (System.IO.Directory.Exists(baseDir))
                {
                    var exeFiles = System.IO.Directory.GetFiles(baseDir, "msedgewebview2.exe", System.IO.SearchOption.AllDirectories);
                    if (exeFiles.Length > 0)
                    {
                        var sorted = exeFiles.Select(f => new System.IO.FileInfo(f))
                                             .OrderByDescending(f => f.LastWriteTime)
                                             .ToList();
                        return sorted[0].FullName;
                    }
                }
            }
            catch { }
            return null;
        }

        public bool IsWebView2Blocked()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\MyFirewall");
                if (key != null)
                {
                    var val = key.GetValue("BlockWebView2Network");
                    if (val is int i && i == 1) return true;
                }
                return false;
            }
            catch { return false; }
        }

        public void SetWebView2Blocked(bool block)
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\MyFirewall");
                key.SetValue("BlockWebView2Network", block ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
            }
            catch (Exception ex) { _logError($"SetWebView2Blocked: {ex.Message}"); }
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
