using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace EncryptDecrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(Constants.VAR_Key, EnvironmentVariableTarget.User)))
            {
                this.Reset_Key_Button.Visibility = Visibility.Collapsed;
            } else
            {
                this.Text_Key.Visibility = Visibility.Collapsed;
                this.Set_Key_Button.Visibility = Visibility.Collapsed;
            }
        }

        private void Set_EncryptionKey(object sender, RoutedEventArgs e)
        {
            Environment.SetEnvironmentVariable(Constants.VAR_Key, this.Text_Key.Text, EnvironmentVariableTarget.User);
            this.Text_Key.Visibility = Visibility.Collapsed;
            this.Set_Key_Button.Visibility = Visibility.Collapsed;
            this.Reset_Key_Button.Visibility = Visibility.Visible;
        }

        private void Reset_EncryptionKey(object sender, RoutedEventArgs e)
        {
            this.Text_Key.Visibility = Visibility.Visible;
            this.Set_Key_Button.Visibility = Visibility.Visible;
            this.Reset_Key_Button.Visibility = Visibility.Collapsed;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var encryptionService = new EncryptionService();
            this.Content.Text = encryptionService.EncryptString(this.Content.Text);
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            var encryptionService = new EncryptionService();
            this.Content.Text = encryptionService.DecryptString(this.Content.Text);
        }
    }
}
