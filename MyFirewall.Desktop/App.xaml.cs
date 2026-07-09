using System;
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

            // The app.manifest requests requireAdministrator, so Windows will enforce UAC
            // elevation before this code is ever reached. This guard is a last-resort
            // defensive check — if the token is somehow non-elevated, log it and continue
            // so the user at least sees the UI and the "No Admin" status badge.
            if (!IsAdministrator())
            {
                System.IO.File.AppendAllText(crashLogPath,
                    $"[{DateTime.Now:s}] WARNING: Process started without an elevated token despite requireAdministrator manifest. Firewall rules will fail.\n");
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
