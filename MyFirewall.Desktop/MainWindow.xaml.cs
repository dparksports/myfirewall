using System.Windows;
using MyFirewall.Desktop.ViewModels;

namespace MyFirewall.Desktop
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Closed(object sender, System.EventArgs e)
        {
            if (DataContext is MainViewModel vm)
            {
                vm.Shutdown();
            }
        }
    }
}
