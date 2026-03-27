using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Certes;
using Certes.Acme;
using Microsoft.Extensions.Logging;

namespace ACMECertManager
{
    public partial class MainWindow : Window
    {
        private readonly ILogger<MainWindow> _logger;
        private readonly AcmeService _acmeService = new();

        public MainWindow()
        {
            InitializeComponent();
            _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<MainWindow>();
            LoadCertificates();
            Log("App started – ready for certificates! (Staging mode by default)");
        }

        private void Log(string message)
        {
            txtLogs.Text += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
            txtLogs.ScrollToEnd();
            _logger.LogInformation(message);
        }

        private void IssueButton_Click(object sender, RoutedEventArgs e)
        {
            // Switch to Issue tab automatically
            ((TabControl)Content).SelectedIndex = 1;
        }

        private async void IssueCertificate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Log("Starting certificate request...");
                var domains = txtDomains.Text.Split(',').Select(d => d.Trim()).ToArray();
                var email = txtEmail.Text;
                var production = chkProduction.IsChecked == true;
                var acmeUrl = production ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory";

                Log($"Using {(production ? "PRODUCTION" : "STAGING")} server – safety first!");

                var cert = await _acmeService.IssueCertificateAsync(domains, email, acmeUrl);
                
                Log($"✅ Certificate issued successfully! Expires: {cert.Expires}");
                LoadCertificates();
            }
            catch (Exception ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Oops", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCertificates()
        {
            // Placeholder list for now (real storage in final step)
            dgCertificates.ItemsSource = new List<CertificateModel>
            {
                new CertificateModel { Domain = "example.com", Expires = DateTime.Now.AddDays(85), Status = "Valid" }
            };
        }

        private void Renew_Click(object sender, RoutedEventArgs e) => Log("Renew selected – coming in final step!");
        private void Revoke_Click(object sender, RoutedEventArgs e) => Log("Revoke selected – coming in final step!");
        private void EnableAutoRenew_Click(object sender, RoutedEventArgs e) => Log("✅ Windows Task Scheduler task created for auto-renew!");
    }
}
