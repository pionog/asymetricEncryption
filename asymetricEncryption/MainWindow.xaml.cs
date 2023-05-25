using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
        bool encrypt = true;
        bool decrypt = false;
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
            string filename = null;
            if (result == true)
            {
                filename = dialog.FileName;
                fileTextBox.Text = filename;
            }
            string extension = System.IO.Path.GetExtension(filename);
            if (extension == ".encrypted")
            {
                modificationGrid.Visibility = Visibility.Visible;
            }
            else {
                modificationGrid.Visibility = Visibility.Hidden;
                if (encrypt == true)
                {
                    encryptionButton.IsChecked = true;
                    decryptionButton.IsChecked = false;
                }
                else {
                    decryptionButton.IsChecked = true;
                    encryptionButton.IsChecked = false;
                }
            }
        }

        private void decryptionButton_Checked(object sender, RoutedEventArgs e)
        {
            decrypt= true;
            encrypt= false;
        }

        private void encryptionButton_Checked(object sender, RoutedEventArgs e)
        {
            decrypt = false;
            encrypt = true;
        }
        private void modificationButton_Checked(object sender, RoutedEventArgs e)
        {
        }

        private void doItButton_Click(object sender, RoutedEventArgs e)
        {
            if (fileTextBox.Text == null || fileTextBox.Text == "")
            {
                MessageBox.Show("You did not select any file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (!Regex.IsMatch(fileTextBox.Text, "^(?:[a-zA-Z]\\:|\\\\\\\\[\\w\\.]+\\\\[\\w.$]+)\\\\(?:[\\w]+\\\\)*\\w([\\w.])+$")) {
                MessageBox.Show("Text You provided is not a valid path.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (encryptionButton.IsChecked == true)
            {
                if (System.IO.Path.GetExtension(fileTextBox.Text) == ".encrypted") {

                    MessageBoxResult dialogResult = MessageBox.Show("You are trying to encrypt already encrypted file. Do You want to proceed furhter?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (dialogResult == MessageBoxResult.No)
                    {
                        return;
                    }
                }
                try
                {
                    Cryptography.Crypt.encrypt(fileTextBox.Text);
                    MessageBox.Show("Encryption has been finished successfully.", "Success");
                }
                catch(Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else if(decryptionButton.IsChecked == true)
            {
                if (!(System.IO.Path.GetExtension(fileTextBox.Text) == ".encrypted"))
                {
                    MessageBox.Show("File should have \".encrypted\" extension.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                try
                {
                    Cryptography.Crypt.decrypt(fileTextBox.Text);
                    MessageBox.Show("Encryption has been finished successfully.", "Success");
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else if(modificationButton.IsChecked == true)
            {
                MessageBoxResult dialogResult = MessageBox.Show("This may result in data loss. Do You want to continue?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Information);
                if (dialogResult == MessageBoxResult.No)
                {
                    return;
                }
                int whichByte;
                try
                {
                    int.TryParse(modificationTextBox.Text, out whichByte);
                }
                catch {
                    throw new ArgumentException("You did not provided valid number.");
                }
                try
                {
                    Cryptography.Crypt.modify(fileTextBox.Text, whichByte);
                }
                catch {
                    throw new ArgumentException("Could not modify file.");
                }
            }
        }

        private void modificationTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        
    }
}
