using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
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

namespace asymmetricEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ProgressReporter progressReporter;
        bool encrypt = true;
        bool decrypt = false;
        public MainWindow()
        {
            InitializeComponent();
            progressReporter = new ProgressReporter();
            progressReporter.ProgressChanged += ProgressReporter_ProgressChanged;
        }

        private void ProgressReporter_ProgressChanged(int progress)
        {
            progressBar.Value = progress;
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

            var watch = System.Diagnostics.Stopwatch.StartNew();


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
                    progressBar.Visibility = Visibility.Visible;
                    fileLabel.Visibility = Visibility.Hidden;
                    progressLabel.Visibility = Visibility.Visible;
                    UpdateLayout();
                    Cryptography.Crypt.encrypt(fileTextBox.Text, progressReporter);
                    successLabel.Visibility = Visibility.Visible;
                    watch.Stop();
                    double elapsedMs = ((double) watch.ElapsedMilliseconds) / 1000;
                    string text = "";
                    if (elapsedMs < 60)
                    {
                        text = String.Format("Encryption has been finished successfully.\nTime elapsed: {0:N1} seconds.", elapsedMs);
                    }
                    else { 
                        int minutes = (int) (elapsedMs / 60);
                        text = String.Format("Encryption has been finished successfully.\nTime elapsed: {0} minutes and {1:N1} seconds", minutes, elapsedMs);
                    }
                    MessageBox.Show(text, "Success");
                }
                catch(Exception ex)
                {
                    progressBar.Foreground = Brushes.Red;
                    failLabel.Visibility = Visibility.Visible;
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    progressBar.Foreground = Brushes.Green;
                }
                progressBar.Visibility = Visibility.Hidden;
                fileLabel.Visibility = Visibility.Visible;
                progressLabel.Visibility = Visibility.Hidden;
                successLabel.Visibility = Visibility.Hidden;
                failLabel.Visibility = Visibility.Hidden;
            }
            else if(decryptionButton.IsChecked == true)
            {
                if (!(System.IO.Path.GetExtension(fileTextBox.Text) == ".encrypted"))
                {
                    MessageBox.Show("File should have \".encrypted\" extension.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                progressBar.Visibility = Visibility.Visible;
                fileLabel.Visibility = Visibility.Hidden;
                progressLabel.Visibility = Visibility.Visible;
                UpdateLayout();
                try
                {
                    Cryptography.Crypt.decrypt(fileTextBox.Text, progressReporter);
                    successLabel.Visibility = Visibility.Visible;
                    watch.Stop();
                    double elapsedMs = ((double)watch.ElapsedMilliseconds) / 1000;
                    string text = "";
                    if (elapsedMs < 60)
                    {
                        text = String.Format("Decryption has been finished successfully.\nTime elapsed: {0:N1} seconds", elapsedMs);
                    }
                    else
                    {
                        int minutes = (int)(elapsedMs / 60);
                        text = String.Format("Decryption has been finished successfully.\nTime elapsed: {0} minutes and {1:N1} seconds", minutes, elapsedMs);
                    }
                    MessageBox.Show(text, "Success");

                }
                catch (Exception ex)
                {
                    progressBar.Foreground = Brushes.Red;
                    failLabel.Visibility = Visibility.Visible;
                    MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    progressBar.Foreground = Brushes.Green;
                }
                progressBar.Visibility = Visibility.Hidden;
                fileLabel.Visibility = Visibility.Visible;
                progressLabel.Visibility = Visibility.Hidden;
                successLabel.Visibility = Visibility.Hidden;
                failLabel.Visibility = Visibility.Hidden;
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
                    MessageBox.Show("You did not provided valid number.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                try
                {
                    Cryptography.Crypt.modify(fileTextBox.Text, whichByte);
                }
                catch {
                    MessageBox.Show("Could not modify file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
        }

        private void worker_ProgressChanged(object? sender, ProgressChangedEventArgs e)
        {
            progressBar.Value = e.ProgressPercentage;
        }

        private void worker_RunWorkerCompleted(object? sender, RunWorkerCompletedEventArgs e)
        {
            progressBar.Value = 100;
        }

        private void modificationTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        private void ProgressBar_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {

        }
    }
}
