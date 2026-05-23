using System.Windows;
using System.Windows.Input;
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

        // Custom Title Bar Dragging
        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                ToggleMaximize();
            }
            else
            {
                DragMove();
            }
        }

        // Handle maximizing when dragged to top of screen
        private void TitleBar_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            if (WindowState == WindowState.Normal && Top < 0)
            {
                WindowState = WindowState.Maximized;
                UpdateMaximizeButton();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void MaximizeButton_Click(object sender, RoutedEventArgs e)
        {
            ToggleMaximize();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void ToggleMaximize()
        {
            if (WindowState == WindowState.Maximized)
            {
                WindowState = WindowState.Normal;
            }
            else
            {
                WindowState = WindowState.Maximized;
            }
            UpdateMaximizeButton();
        }

        private void UpdateMaximizeButton()
        {
            if (MaximizeBtn != null)
            {
                MaximizeBtn.Content = WindowState == WindowState.Maximized ? "❐" : "□";
            }
        }
    }
}
