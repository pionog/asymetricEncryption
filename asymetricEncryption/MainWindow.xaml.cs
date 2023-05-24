using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
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

namespace asymetricEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void TextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            //string path = fileTextBox.Text;
        }

        private void selectFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog();
            bool? result = dialog.ShowDialog();
            if (result == true)
            {
                string filename = dialog.FileName;
                fileTextBox.Text = filename;
            }
        }

        private void decryptionButton_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void encryptionButton_Checked(object sender, RoutedEventArgs e)
        {

        }

        private void doItButton_Click(object sender, RoutedEventArgs e)
        {
            if(encryptionButton.IsChecked == true)
            {
                try
                {
                    byte[] encryptedFile = Cryptography.Crypt.encrypt(fileTextBox.Text);
                    string text = Convert.ToBase64String(encryptedFile);
                    File.WriteAllText(fileTextBox.Text + ".encrypted", text);
                    MessageBox.Show("Encryption has been ended successfully.", "Success");
                }
                catch(Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else if(decryptionButton.IsChecked == true)
            {
                try
                {
                    byte[] decryptedFile = Cryptography.Crypt.decrypt(fileTextBox.Text);
                    string file = System.IO.Path.GetFileNameWithoutExtension(fileTextBox.Text);
                    string fileWE = System.IO.Path.GetFileNameWithoutExtension(file);
                    string extension = System.IO.Path.GetExtension(file);
                    string fileResult = fileWE + "_result" + extension;
                    string path = System.IO.Path.GetDirectoryName(fileTextBox.Text);
                    string fileName = System.IO.Path.Combine(path, fileResult);
                    File.WriteAllBytes(fileName, decryptedFile);
                    MessageBox.Show("Decryption has been ended successfully.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }
}
