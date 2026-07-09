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

            // FIX: Self-elevate if not running as Administrator.
            // The app.manifest declares requireAdministrator, but this is NOT reliable
            // in all launch scenarios (parent process is non-elevated, Task Scheduler,
            // certain deployment tools, etc.). When the token is non-elevated, re-launch
            // the EXE with Verb="runas" to trigger an explicit UAC prompt, then exit
            // this non-elevated instance. This matches the CLI's RestartAsAdmin() pattern.
            if (!IsAdministrator())
            {
                try
                {
                    string exePath = Process.GetCurrentProcess().MainModule?.FileName
                                     ?? System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MyFirewall.Desktop.exe");

                    Process.Start(new ProcessStartInfo
                    {
                        FileName         = exePath,
                        UseShellExecute  = true,
                        Verb             = "runas",
                        WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory
                    });
                }
                catch (Exception ex)
                {
                    // User cancelled UAC prompt or elevation failed — show a message and exit.
                    System.IO.File.AppendAllText(crashLogPath,
                        $"[{DateTime.Now:s}] ELEVATION FAILED: {ex.Message}\n");
                    MessageBox.Show(
                        "MyFirewall requires Administrator privileges to manage firewall rules.\n\n" +
                        "Please right-click the application and select 'Run as administrator'.",
                        "MyFirewall - Elevation Required",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }

                // Shut down this non-elevated instance either way.
                Shutdown();
                return;
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

    }
}
