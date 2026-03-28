using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Extensions.Logging;

namespace ACMECertManager
{
    public partial class MainWindow : Window
    {
        private readonly ILogger<MainWindow> _logger;
        private readonly AcmeService _acmeService = new();
        private List<CertificateModel> _certificates = new();
        private readonly Dictionary<string, TextBox> _dnsFieldInputs = new(StringComparer.OrdinalIgnoreCase);
        private LogManager? _logManager;
        private List<LoadedDnsPlugin> _availablePlugins = new();
        private Dictionary<string, IReadOnlyList<DnsCredentialField>> _pluginFields = new(StringComparer.OrdinalIgnoreCase);

        public MainWindow()
        {
            InitializeComponent();
            _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<MainWindow>();
            
            // Initialize LogManager with the max size from app settings
            var app = (App)Application.Current;
            _logManager = new LogManager(RuntimePaths.LogsDirectory, app.MaxLogFileSizeMb);
            
            UpdateAdminRelaunchVisibility();
            SetAdvancedSettingsSelection(app.SavePemChainArtifacts);
            SetMaxLogFileSizeInput(app.MaxLogFileSizeMb);
            
            _certificates = CertificateStorage.Load();
            LoadCertificatesGrid();
            LoadDnsPlugins();
            UpdateValidationUiState();
            
            // Load persisted logs if they exist
            LoadPersistedLogs();
            
            Log("🚀 ACME Certificate Manager started! Default = staging mode (safe)");
        }

        private void Log(string message)
        {
            txtLogs.Text += $"[{DateTime.Now:HH:mm:ss}] {message}\n";
            txtLogs.ScrollToEnd();
            _logger.LogInformation(message);

            try
            {
                _logManager?.WriteLog(message);
            }
            catch
            {
                // Keep running if persistent logging fails
            }
            
            UpdateLogStatistics();
        }

        private void SetAdvancedSettingsSelection(bool savePemChainArtifacts)
        {
            if (chkSavePemChainArtifacts is null)
            {
                return;
            }

            chkSavePemChainArtifacts.IsChecked = savePemChainArtifacts;
        }

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
                var validationMethod = rbDns.IsChecked == true ? ChallengeValidationMethod.Dns01 : ChallengeValidationMethod.Http01;
                var savePemChainArtifacts = ((App)Application.Current).SavePemChainArtifacts;

                Log($"Using {(production ? "PRODUCTION ⚠️" : "STAGING (safe)")} server");

                DnsPluginExecution? dnsExecution = null;
                if (validationMethod == ChallengeValidationMethod.Dns01)
                {
                    if (cmbDnsPlugin.SelectedItem is not LoadedDnsPlugin loadedPlugin)
                    {
                        throw new Exception("Select a DNS plugin before issuing a DNS-01 certificate.");
                    }

                    var credentials = CollectDnsCredentials(loadedPlugin);
                    var warning = MessageBox.Show(
                        "DNS plugin secrets are currently stored as plaintext in storage/dns-secrets.json. Continue?",
                        "Security Warning",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);

                    if (warning != MessageBoxResult.Yes)
                    {
                        Log("DNS issuance canceled by user after plaintext warning.");
                        return;
                    }

                    DnsSecretStorage.SaveForPlugin(loadedPlugin.Metadata.Id, credentials);
                    dnsExecution = new DnsPluginExecution
                    {
                        Plugin = loadedPlugin,
                        Credentials = credentials
                    };
                }

                var cert = await _acmeService.IssueCertificateAsync(domains, email, acmeUrl, validationMethod, dnsExecution, savePemChainArtifacts, Log);

                _certificates.Add(cert);
                CertificateStorage.Save(_certificates);
                LoadCertificatesGrid();

                Log($"✅ SUCCESS! Certificate for {cert.Domain} issued. Expires {cert.Expires:yyyy-MM-dd}");
                MessageBox.Show($"Certificate saved to {cert.PfxPath}\n\nTip: Reload your web server (IIS/Nginx)", "Success!", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadCertificatesGrid()
        {
            dgCertificates.ItemsSource = null;
            dgCertificates.ItemsSource = _certificates;
            dgCertificates.Items.Refresh();
        }

        private void RelaunchAsAdmin_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (IsRunningAsAdministrator())
                {
                    UpdateAdminRelaunchVisibility();
                    Log("Already running as Administrator.");
                    MessageBox.Show("This app is already running as Administrator.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                var currentExe = Environment.ProcessPath;
                if (string.IsNullOrWhiteSpace(currentExe))
                {
                    throw new InvalidOperationException("Unable to locate current executable path.");
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = currentExe,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(startInfo);
                Log("Launched elevated instance. Closing current window...");
                Close();
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                Log("Administrator relaunch canceled by user.");
            }
            catch (Exception ex)
            {
                Log($"Failed to re-launch as Administrator: {ex.Message}");
                MessageBox.Show(ex.Message, "Elevation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                UpdateAdminRelaunchVisibility();
            }
        }

        private void UpdateAdminRelaunchVisibility()
        {
            txtRelaunchAsAdmin.Visibility = IsRunningAsAdministrator() ? Visibility.Collapsed : Visibility.Visible;
        }

        private static bool IsRunningAsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void Renew_Click(object sender, RoutedEventArgs e)
        {
            if (dgCertificates.SelectedItem is CertificateModel cert)
                Log($"🔄 Renewing {cert.Domain} (full renew ready in v1.1)");
        }

        private void Revoke_Click(object sender, RoutedEventArgs e)
        {
            if (dgCertificates.SelectedItem is CertificateModel cert)
                _ = RevokeSelectedCertificateAsync(cert);
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (dgCertificates.SelectedItem is not CertificateModel cert)
            {
                return;
            }

            var confirmed = MessageBox.Show(
                $"Delete local certificate files and metadata for {cert.Domain}?",
                "Delete Certificate",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmed != MessageBoxResult.Yes)
            {
                return;
            }

            try
            {
                if (!string.IsNullOrWhiteSpace(cert.PfxPath) && File.Exists(cert.PfxPath))
                {
                    File.Delete(cert.PfxPath);
                }

                _certificates.Remove(cert);
                CertificateStorage.Save(_certificates);
                LoadCertificatesGrid();
                Log($"🗑 Deleted local certificate for {cert.Domain}");
            }
            catch (Exception ex)
            {
                Log($"❌ Delete failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ValidationMethod_Checked(object sender, RoutedEventArgs e)
        {
            UpdateValidationUiState();
        }

        private void UpdateValidationUiState()
        {
            if (rbDns is null || rbHttp is null || grpDnsPlugin is null || txtRelaunchAsAdmin is null)
            {
                return;
            }

            var dnsSelected = rbDns.IsChecked == true;
            grpDnsPlugin.Visibility = dnsSelected ? Visibility.Visible : Visibility.Collapsed;
            txtRelaunchAsAdmin.Visibility = rbHttp.IsChecked == true && !IsRunningAsAdministrator()
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void LoadDnsPlugins()
        {
            var discovery = DnsPluginLoader.DiscoverPlugins(RuntimePaths.PluginsDirectory);
            _availablePlugins = discovery.Plugins
                .OrderBy(p => p.Metadata.DisplayName, StringComparer.OrdinalIgnoreCase)
                .ToList();
            
            // Build plugin fields dictionary for secrets window
            _pluginFields.Clear();
            foreach (var plugin in _availablePlugins)
            {
                _pluginFields[plugin.Metadata.Id] = plugin.Instance.GetCredentialFields();
            }
            
            cmbDnsPlugin.ItemsSource = _availablePlugins;

            if (cmbDnsPlugin.Items.Count > 0)
            {
                cmbDnsPlugin.SelectedIndex = 0;
            }

            foreach (var warning in discovery.Warnings)
            {
                Log($"⚠️ {warning}");
            }

            if (discovery.Plugins.Count == 0)
            {
                Log("No DNS plugins found in plugins folder.");
            }
            else
            {
                Log($"Loaded {discovery.Plugins.Count} DNS plugin(s).");
            }
        }

        private void DnsPluginSelection_Changed(object sender, SelectionChangedEventArgs e)
        {
            BuildDnsCredentialInputs();
        }

        private void BuildDnsCredentialInputs()
        {
            pnlDnsFields.Children.Clear();
            _dnsFieldInputs.Clear();

            if (cmbDnsPlugin.SelectedItem is not LoadedDnsPlugin selected)
            {
                txtPluginDescription.Text = "No plugin selected.";
                return;
            }

            txtPluginDescription.Text = selected.Metadata.Description;
            
            // Get all stored credentials for this plugin
            var allCredentials = DnsSecretStorage.GetCredentialsForPlugin(selected.Metadata.Id);
            
            // If there are saved credentials, show a selector
            if (allCredentials.Count > 0)
            {
                var selectLabel = new TextBlock
                {
                    Text = "Stored Credentials",
                    Margin = new Thickness(0, 4, 0, 2),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold
                };
                pnlDnsFields.Children.Add(selectLabel);

                var credentialCombo = new ComboBox
                {
                    Height = 34,
                    Margin = new Thickness(0, 0, 0, 12)
                };

                credentialCombo.Items.Add(new ComboBoxItem { Content = "(use new/custom credentials)" });
                
                foreach (var cred in allCredentials)
                {
                    var displayName = string.IsNullOrEmpty(cred.Domain) ? "(default)" : cred.Domain;
                    credentialCombo.Items.Add(new ComboBoxItem { Content = displayName, Tag = cred });
                }

                credentialCombo.SelectedIndex = 0;
                credentialCombo.SelectionChanged += (s, e) =>
                {
                    if (credentialCombo.SelectedItem is ComboBoxItem item && item.Tag is DnsSecretCredential selectedCred)
                    {
                        // Pre-populate fields from selected credential
                        PopulateDnsFieldsFromCredential(selected, selectedCred.Values);
                    }
                    else
                    {
                        // Clear fields for new credentials
                        ClearDnsFields(selected);
                    }
                };

                pnlDnsFields.Children.Add(credentialCombo);
            }

            // Build the input fields
            var savedValues = DnsSecretStorage.GetForPlugin(selected.Metadata.Id);

            foreach (var field in selected.Instance.GetCredentialFields())
            {
                var label = new TextBlock
                {
                    Text = field.IsRequired ? $"{field.Label} *" : field.Label,
                    Margin = new Thickness(0, 4, 0, 2),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold
                };
                pnlDnsFields.Children.Add(label);

                var input = new TextBox
                {
                    Height = 34,
                    Padding = new Thickness(8, 4, 8, 4),
                    ToolTip = field.Placeholder
                };

                if (savedValues.TryGetValue(field.Name, out var existingValue))
                {
                    input.Text = existingValue;
                }

                _dnsFieldInputs[field.Name] = input;
                pnlDnsFields.Children.Add(input);

                if (!string.IsNullOrWhiteSpace(field.Placeholder))
                {
                    pnlDnsFields.Children.Add(new TextBlock
                    {
                        Text = field.Placeholder,
                        Margin = new Thickness(0, 2, 0, 6),
                        FontSize = 11,
                        Foreground = SystemColors.GrayTextBrush
                    });
                }
            }
        }

        private void PopulateDnsFieldsFromCredential(LoadedDnsPlugin plugin, IReadOnlyDictionary<string, string> credentials)
        {
            foreach (var field in plugin.Instance.GetCredentialFields())
            {
                if (_dnsFieldInputs.TryGetValue(field.Name, out var input))
                {
                    if (credentials.TryGetValue(field.Name, out var value))
                    {
                        input.Text = value;
                    }
                    else
                    {
                        input.Text = string.Empty;
                    }
                }
            }
        }

        private void ClearDnsFields(LoadedDnsPlugin plugin)
        {
            foreach (var field in plugin.Instance.GetCredentialFields())
            {
                if (_dnsFieldInputs.TryGetValue(field.Name, out var input))
                {
                    input.Text = string.Empty;
                }
            }
        }

        private Dictionary<string, string> CollectDnsCredentials(LoadedDnsPlugin plugin)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var field in plugin.Instance.GetCredentialFields())
            {
                if (!_dnsFieldInputs.TryGetValue(field.Name, out var input))
                {
                    throw new InvalidOperationException($"Missing input for '{field.Label}'.");
                }

                var value = input.Text?.Trim() ?? string.Empty;
                if (field.IsRequired && string.IsNullOrWhiteSpace(value))
                {
                    throw new InvalidOperationException($"'{field.Label}' is required for plugin '{plugin.Metadata.DisplayName}'.");
                }

                values[field.Name] = value;
            }

            return values;
        }

        private async System.Threading.Tasks.Task RevokeSelectedCertificateAsync(CertificateModel cert)
        {
            try
            {
                Log($"⛔ Revoking {cert.Domain} via CA...");
                await _acmeService.RevokeCertificateAsync(cert);
                cert.Status = "Revoked";
                CertificateStorage.Save(_certificates);
                LoadCertificatesGrid();
                Log($"✅ Revoked {cert.Domain}");
            }
            catch (Exception ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ViewDnsSecrets_Click(object sender, RoutedEventArgs e)
        {
            var all = DnsSecretStorage.LoadAll();
            if (all.Count == 0)
            {
                MessageBox.Show("No DNS plugin secrets are currently stored.", "Stored DNS Secrets", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var secretsWindow = new DnsSecretsWindow(_availablePlugins, _pluginFields)
            {
                Owner = this
            };
            secretsWindow.ShowDialog();
        }

        private void SavePemChainArtifacts_Changed(object sender, RoutedEventArgs e)
        {
            if (chkSavePemChainArtifacts is null)
            {
                return;
            }

            var enabled = chkSavePemChainArtifacts.IsChecked == true;
            ((App)Application.Current).SetSavePemChainArtifacts(enabled);
            Log(enabled
                ? "Advanced output enabled: will save PEM artifacts with each issued certificate."
                : "Advanced output disabled: only PFX will be saved by default.");
        }

        private void SetMaxLogFileSizeInput(int sizeMb)
        {
            if (txtMaxLogFileSizeMb is null)
            {
                return;
            }

            txtMaxLogFileSizeMb.Text = sizeMb.ToString();
        }

        private void MaxLogFileSize_Changed(object sender, TextChangedEventArgs e)
        {
            if (txtMaxLogFileSizeMb is null || string.IsNullOrWhiteSpace(txtMaxLogFileSizeMb.Text))
            {
                return;
            }

            if (int.TryParse(txtMaxLogFileSizeMb.Text, out var sizeMb) && sizeMb > 0)
            {
                var app = (App)Application.Current;
                app.SetMaxLogFileSizeMb(sizeMb);
                
                // Update LogManager with new size limit
                if (_logManager != null)
                {
                    _logManager.Dispose();
                    _logManager = new LogManager(RuntimePaths.LogsDirectory, sizeMb);
                }
                
                Log($"📊 Log file size limit changed to {sizeMb} MB");
            }
        }

        private void LoadPersistedLogs()
        {
            try
            {
                if (_logManager == null)
                    return;

                var logFiles = _logManager.GetAllLogFiles();
                if (logFiles.Length == 0)
                    return;

                var sb = new System.Text.StringBuilder();
                
                // Load the most recent log file (main log)
                if (File.Exists(logFiles[0]))
                {
                    try
                    {
                        var content = File.ReadAllText(logFiles[0]);
                        sb.Append(content);
                    }
                    catch
                    {
                        // Skip if we can't read
                    }
                }

                if (sb.Length > 0)
                {
                    txtLogs.Text = sb.ToString();
                    txtLogs.ScrollToEnd();
                }

                UpdateLogStatistics();
            }
            catch
            {
                // Silently fail if we can't load persisted logs
            }
        }

        private void UpdateLogStatistics()
        {
            try
            {
                if (_logManager == null || txtLogStats == null)
                    return;

                var (fileCount, totalSize) = _logManager.GetLogStatistics();
                var sizeMb = totalSize / (1024.0 * 1024.0);
                var currentSizeMb = _logManager.GetCurrentLogFileSizeBytes() / (1024.0 * 1024.0);

                txtLogStats.Text = $"📊 Total: {totalSize:N0} bytes ({sizeMb:F2} MB) | Current: {currentSizeMb:F2} MB | Files: {fileCount}";
            }
            catch
            {
                // Silently fail
            }
        }

        private void ExportLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_logManager == null)
                {
                    MessageBox.Show("Log manager not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var dialog = new Microsoft.Win32.SaveFileDialog
                {
                    FileName = $"ACME_Logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                    DefaultExt = ".txt",
                    Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
                };

                if (dialog.ShowDialog() == true)
                {
                    _logManager.ExportLogs(dialog.FileName);
                    Log($"✅ Logs exported to {Path.GetFileName(dialog.FileName)}");
                    MessageBox.Show($"Logs exported successfully to:\n{dialog.FileName}", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                Log($"❌ Failed to export logs: {ex.Message}");
                MessageBox.Show($"Failed to export logs: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ClearLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_logManager == null)
                {
                    MessageBox.Show("Log manager not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var confirmed = MessageBox.Show(
                    "Clear all log files? This action cannot be undone.",
                    "Clear Logs",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (confirmed == MessageBoxResult.Yes)
                {
                    _logManager.ClearLogs();
                    txtLogs.Text = string.Empty;
                    UpdateLogStatistics();
                    Log("✅ All logs cleared");
                }
            }
            catch (Exception ex)
            {
                Log($"❌ Failed to clear logs: {ex.Message}");
                MessageBox.Show($"Failed to clear logs: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
