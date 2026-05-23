using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Windows;
using MyFirewall.Desktop.ViewModels;

namespace MyFirewall.Desktop
{
    public partial class App : Application
    {
        private void Application_Startup(object sender, StartupEventArgs e)
        {
            if (!IsAdministrator())
            {
                MessageBox.Show("TCP Monitor Desktop requires Administrator privileges for ETW tracing.\nRestarting...", "Admin Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                RestartAsAdmin();
                Shutdown();
                return;
            }

            MainWindow = new MainWindow();
            MainWindow.Show();
        }

        private bool IsAdministrator()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void RestartAsAdmin()
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = Process.GetCurrentProcess().MainModule!.FileName,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Environment.CurrentDirectory
            };
            try
            {
                Process.Start(processInfo);
            }
            catch
            {
                // User cancelled UAC
            }
        }
    }
}
