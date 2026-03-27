using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.TaskScheduler;

namespace ACMECertManager
{
    public partial class MainWindow : Window
    {
        private readonly ILogger<MainWindow> _logger;
        private readonly AcmeService _acmeService = new();
        private List<CertificateModel> _certificates = new();

        public MainWindow()
        {
            InitializeComponent();
            _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<MainWindow>();
            _certificates = CertificateStorage.Load();
            LoadCertificatesGrid();
            Log("🚀 Grok ACME Certificate Manager started! Default = staging mode (safe)");
        }

        private void Log(string message)
        {
            txtLogs.Text += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
            txtLogs.ScrollToEnd();
            _logger.LogInformation(message);
        }

        private void IssueButton_Click(object sender, RoutedEventArgs e) => ((TabControl)Content).SelectedIndex = 1;

        private async void IssueCertificate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Log("Starting certificate issuance...");
                var domains = txtDomains.Text.Split(',').Select(d => d.Trim()).Where(d => !string.IsNullOrEmpty(d)).ToArray();
                if (domains.Length == 0) throw new Exception("Enter at least one domain");

                var email = txtEmail.Text;
                if (string.IsNullOrEmpty(email)) throw new Exception("Email required");

                var production = chkProduction.IsChecked == true;
                var acmeUrl = production ? "https://acme-v02.api.letsencrypt.org/directory" : "https://acme-staging-v02.api.letsencrypt.org/directory";

                Log($"Using {(production ? "PRODUCTION ⚠️" : "STAGING (safe)")} server");

                var cert = await _acmeService.IssueCertificateAsync(domains, email, acmeUrl);

                _certificates.Add(cert);
                CertificateStorage.Save(_certificates);
                LoadCertificatesGrid();

                Log($"✅ SUCCESS! Certificate for {cert.Domain} issued. Expires {cert.Expires:yyyy-MM-dd}");
                MessageBox.Show($"Certificate saved to certs/{cert.Domain}.pfx\n\nTip: Reload your web server (IIS/Nginx)", "Success!", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCertificatesGrid() => dgCertificates.ItemsSource = _certificates;

        private void Renew_Click(object sender, RoutedEventArgs e)
        {
            if (dgCertificates.SelectedItem is CertificateModel cert)
                Log($"🔄 Renewing {cert.Domain} (full renew ready in v1.1)");
        }

        private void Revoke_Click(object sender, RoutedEventArgs e)
        {
            if (dgCertificates.SelectedItem is CertificateModel cert)
                Log($"⛔ Revoking {cert.Domain} (full revoke ready in v1.1)");
        }

        private void EnableAutoRenew_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                using var ts = new TaskService();
                var definition = ts.NewTask();
                definition.Triggers.Add(new DailyTrigger { DaysInterval = 60 });
                definition.Actions.Add(new ExecAction(System.AppContext.BaseDirectory, "--renew", null));
                definition.Settings.Enabled = true;
                ts.RootFolder.RegisterTaskDefinition("GrokACMECertManager_Renew", definition,
                    TaskCreation.CreateOrUpdate, null, null, TaskLogonType.InteractiveToken);
                Log("✅ Auto-renew task created in Windows Task Scheduler!");
                MessageBox.Show("Auto-renew scheduled every 60 days!", "Success");
            }
            catch (Exception ex)
            {
                Log($"Task Scheduler error: {ex.Message}");
            }
        }
    }
}
