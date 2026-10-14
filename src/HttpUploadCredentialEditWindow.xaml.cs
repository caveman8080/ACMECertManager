using System;
using System.IO;
using System.Windows;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace ACMECertManager
{
    public partial class HttpUploadCredentialEditWindow : Wpf.Ui.Controls.FluentWindow
    {
        private readonly HttpUploadCredentialRecord _record;

        public HttpUploadCredentialEditWindow(HttpUploadCredentialRecord record)
        {
            InitializeComponent();
            _record = record;
            txtDomain.Text = string.IsNullOrWhiteSpace(record.Domain) ? "(unnamed certificate)" : record.Domain;
            txtOutputDirectory.Text = string.IsNullOrWhiteSpace(record.OutputDirectory) ? "(not set)" : record.OutputDirectory;
            txtMethod.Text = record.DeploymentMethod;
            txtTarget.Text = record.Target;
            txtPort.Text = record.Port?.ToString() ?? string.Empty;
            txtUsername.Text = record.Username;
            txtPassword.Password = record.Password ?? string.Empty;
            txtBearerToken.Password = record.BearerToken ?? string.Empty;
            txtHeaderValue.Text = record.AdditionalHeaderValue ?? string.Empty;
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            int? port = null;
            var rawPort = txtPort.Text?.Trim() ?? string.Empty;
            if (rawPort.Length > 0)
            {
                if (!int.TryParse(rawPort, out var parsed))
                {
                    MessageBox.Show(
                        "Port must be a whole number from 1 to 65535, or left blank.",
                        "HTTP Upload Credentials",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                    return;
                }

                port = parsed;
            }

            var certificates = CertificateStorage.Load();
            var edit = new HttpUploadCredentialRecord
            {
                Domain = _record.Domain,
                OutputDirectory = _record.OutputDirectory,
                DeploymentMethod = _record.DeploymentMethod,
                Target = txtTarget.Text ?? string.Empty,
                Port = port,
                Username = txtUsername.Text ?? string.Empty,
                Password = txtPassword.Password ?? string.Empty,
                BearerToken = txtBearerToken.Password ?? string.Empty,
                AdditionalHeaderValue = txtHeaderValue.Text ?? string.Empty
            };

            if (!HttpUploadCredentialStore.TryApply(certificates, edit, out var error))
            {
                MessageBox.Show(error, "HTTP Upload Credentials", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                CertificateStorage.Save(certificates);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                MessageBox.Show(
                    $"Could not write certificates.json.\n\n{ex.Message}",
                    "HTTP Upload Credentials",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }

            DialogResult = true;
            Close();
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
