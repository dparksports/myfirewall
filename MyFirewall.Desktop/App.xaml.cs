using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using MyFirewall.Desktop.ViewModels;

namespace MyFirewall.Desktop
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Setup global crash logging
            string crashLogPath = System.IO.Path.GetFullPath(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "crash.log"));
            
            this.DispatcherUnhandledException += (s, args) =>
            {
                System.IO.File.AppendAllText(crashLogPath, $"[{DateTime.Now:s}] UI CRASH: {args.Exception}\n");
                args.Handled = true; // Prevent immediate shutdown if possible
            };

            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                System.IO.File.AppendAllText(crashLogPath, $"[{DateTime.Now:s}] BACKGROUND CRASH: {args.ExceptionObject}\n");
            };

            if (!IsAdministrator())
            {
                // Silent auto-elevation without the jarring MessageBox
                if (RestartAsAdmin())
                {
                    Shutdown();
                    return;
                }
                else
                {
                    // User cancelled UAC prompt or it failed.
                    // Instead of failing silently, launch anyway in degraded mode.
                    // The UI will show a red "No Admin" badge and ETW will fail gracefully.
                }
            }

            MainWindow = new MainWindow();
            MainWindow.Show();
        }

        private bool IsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private bool RestartAsAdmin()
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName ?? "MyFirewall.Desktop.exe",
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.CurrentDirectory
            };
            
            try
            {
                Process.Start(processInfo);
                return true;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // Win32Exception is thrown if user cancels the UAC prompt
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
