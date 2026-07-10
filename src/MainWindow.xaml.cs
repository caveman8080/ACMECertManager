using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using ACMECertManager;

namespace ACMECertManager
{
    public partial class MainWindow : Window
    {
        private readonly AcmeService _acmeService = new();
        private CancellationTokenSource? _issuanceCts;

        public MainWindow()
        {
            InitializeComponent();
            // ... existing constructor code ...
            Log("🚀 ACME Certificate Manager started! Default = production mode");
        }

        // ... existing fields and other methods ...

        // Example issuance method (the actual call site from previous code)
        private async Task PerformCertificateIssuance(string[] domains, string email, string acmeUrl, 
            ChallengeValidationMethod validationMethod, HttpChallengeDeploymentOptions? httpDeployment, 
            DnsPluginExecution? dnsExecution, bool createPfxFile)
        {
            _issuanceCts = new CancellationTokenSource();
            try
            {
                var cert = await _acmeService.IssueCertificateAsync(
                    domains, email, acmeUrl, validationMethod, httpDeployment, dnsExecution, createPfxFile, Log, _issuanceCts.Token);

                if (createPfxFile && (string.IsNullOrWhiteSpace(cert.PfxPath) || !File.Exists(cert.PfxPath)))
                {
                    Log("[WARNING] PFX file was requested but not created or not found on disk.");
                }

                // Existing post-issuance logic (reload certificates, select in grid, etc.)
                // ... (keep your existing code here)
            }
            catch (OperationCanceledException)
            {
                Log("[INFO] Certificate issuance was cancelled by the user.");
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Issuance failed: {ex.Message}");
                // existing error handling
            }
            finally
            {
                _issuanceCts?.Dispose();
                _issuanceCts = null;
            }
        }

        /// <summary>
        /// Call this method from a Cancel button Click handler in the Issue New Certificate tab.
        /// Example XAML: <Button Content="Cancel Issuance" Click="CancelIssuance_Click" />
        /// </summary>
        private void CancelCurrentIssuance()
        {
            if (_issuanceCts != null && !_issuanceCts.IsCancellationRequested)
            {
                _issuanceCts.Cancel();
                Log("[INFO] Cancellation requested...");
            }
        }

        // Example event handler for Cancel button (add to your XAML and wire up)
        private void CancelIssuance_Click(object sender, RoutedEventArgs e)
        {
            CancelCurrentIssuance();
        }

        // ... rest of your existing MainWindow code ...
    }
}
