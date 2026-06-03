using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

using System.Windows.Media;
using System.Windows.Media.Animation;
using Wpf.Ui.Appearance;
// screenshot capture removed
using Microsoft.Extensions.Logging;

namespace ACMECertManager
{
    public partial class MainWindow : Wpf.Ui.Controls.FluentWindow
    {
        private readonly ILogger<MainWindow> _logger;
        private readonly AcmeService _acmeService = new();
        private List<CertificateModel> _certificates = new();
        private readonly Dictionary<string, System.Windows.Controls.TextBox> _dnsFieldInputs = new(StringComparer.OrdinalIgnoreCase);
        private LogManager? _logManager;
        private List<LoadedDnsPlugin> _availablePlugins = new();
        private readonly Dictionary<string, IReadOnlyList<DnsCredentialField>> _pluginFields = new(StringComparer.OrdinalIgnoreCase);
        private bool _isSyncingNavSelection;
        private readonly Stack<string> _navigationHistory = new();
        private string _currentPageKey = "Manage";

        public MainWindow()
        {
            SystemThemeWatcher.Watch(this);

            InitializeComponent();
            _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<MainWindow>();

            Loaded += (_, _) => InitializeNavigation();

            // Initialize LogManager with the max size from app settings
            var app = (App)Application.Current;
            _logManager = new LogManager(RuntimePaths.LogsDirectory, app.MaxLogFileSizeMb);

            UpdateAdminRelaunchVisibility();
            SetMaxLogFileSizeInput(app.MaxLogFileSizeMb);
            SetAppearanceThemeSelection(app.ThemePreference);

            _certificates = CertificateStorage.Load();
            LoadCertificatesGrid();
            LoadDnsPlugins();
            UpdateValidationUiState();

            // Load persisted logs if they exist
            LoadPersistedLogs();

            Log("🚀 ACME Certificate Manager started! Default = production mode");
        }

        private void InitializeNavigation()
        {
            if ((NavPrimaryMenu?.MenuItems?.Count ?? 0) == 0 && (NavPrimaryMenu?.FooterMenuItems?.Count ?? 0) == 0)
            {
                return;
            }

            NavigateToPage("Manage", pushHistory: false);
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
            catch (ObjectDisposedException)
            {
                // Keep running if persistent logging fails
            }

            UpdateLogStatistics();
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

                var acmeUrl = ResolveAcmeDirectoryUrl();
                var validationMethod = rbDns.IsChecked == true
                    ? ChallengeValidationMethod.Dns01
                    : rbTls.IsChecked == true
                        ? ChallengeValidationMethod.TlsAlpn01
                        : ChallengeValidationMethod.Http01;

                var hasWildcardDomain = domains.Any(d => d.StartsWith("*.", StringComparison.Ordinal));
                if (hasWildcardDomain && validationMethod != ChallengeValidationMethod.Dns01)
                {
                    throw new InvalidOperationException("Wildcard domains can only be used with DNS validation. Please choose DNS validation for names such as *.example.com.");
                }

                var httpDeployment = BuildHttpDeploymentOptions(validationMethod);
                var createPfxFile = chkCreatePfxFile.IsChecked == true;

                var usingStaging = AcmeService.IsStagingDirectoryUrl(acmeUrl);
                Log($"Using {(usingStaging ? "STAGING (safe)" : "PRODUCTION")} server");
                if (!string.Equals(acmeUrl, AcmeService.LetsEncryptProductionDirectoryUrl, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(acmeUrl, AcmeService.LetsEncryptStagingDirectoryUrl, StringComparison.OrdinalIgnoreCase))
                {
                    Log($"Using custom ACME directory URL: {acmeUrl}");
                }

                DnsPluginExecution? dnsExecution = null;
                if (validationMethod == ChallengeValidationMethod.Dns01)
                {
                    if (cmbDnsPlugin.SelectedItem is not LoadedDnsPlugin loadedPlugin)
                    {
                        throw new Exception("Select a DNS plugin before issuing a DNS-01 certificate.");
                    }

                    var credentials = CollectDnsCredentials(loadedPlugin);
                    var warning = System.Windows.MessageBox.Show(
                        "DNS plugin secrets are currently stored as plaintext in storage/dns-secrets.json. Continue?",
                        "Security Warning",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Warning);

                    if (warning != System.Windows.MessageBoxResult.Yes)
                    {
                        Log("DNS issuance canceled by user after plaintext warning.");
                        return;
                    }

                    DnsSecretStorage.SaveForPlugin(loadedPlugin.Metadata.Id, credentials, GetDnsSecretDomainContext(domains));
                    dnsExecution = new DnsPluginExecution
                    {
                        Plugin = loadedPlugin,
                        Credentials = credentials
                    };
                }

                var cert = await _acmeService.IssueCertificateAsync(domains, email, acmeUrl, validationMethod, httpDeployment, dnsExecution, createPfxFile, Log);

                if (createPfxFile && (string.IsNullOrWhiteSpace(cert.PfxPath) || !File.Exists(cert.PfxPath)))
                {
                    throw new InvalidOperationException("PFX output was requested, but certificate.pfx was not created.");
                }

                var existingIndex = _certificates.FindIndex(existing =>
                    string.Equals(existing.OutputDirectory, cert.OutputDirectory, StringComparison.OrdinalIgnoreCase));
                if (existingIndex >= 0)
                {
                    _certificates[existingIndex] = cert;
                }
                else
                {
                    _certificates.Add(cert);
                }

                CertificateStorage.Save(_certificates);
                _certificates = CertificateStorage.Load();
                LoadCertificatesGrid();

                Log($"✅ SUCCESS! Certificate for {cert.Domain} issued. Expires {cert.Expires:yyyy-MM-dd}");
                var outputSummary = createPfxFile && !string.IsNullOrWhiteSpace(cert.PfxPath)
                    ? $"PEM + PFX files saved in:\n{cert.OutputDirectory}"
                    : $"PEM files saved in:\n{cert.OutputDirectory}";
                System.Windows.MessageBox.Show($"{outputSummary}\n\nTip: Reload your web server (IIS/Nginx)", "Success!", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            }
            catch (InvalidOperationException ex)
            {
                Log($"❌ Error: {ex.Message}");
                System.Windows.MessageBox.Show(ex.Message, "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            catch (ArgumentException ex)
            {
                Log($"❌ Error: {ex.Message}");
                System.Windows.MessageBox.Show(ex.Message, "Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (UnauthorizedAccessException ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.Security.SecurityException ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (HttpRequestException ex)
            {
                Log($"❌ Error: {ex.Message}");
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (TaskCanceledException ex)
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
            catch (InvalidOperationException ex)
            {
                Log($"Failed to re-launch as Administrator: {ex.Message}");
                MessageBox.Show(ex.Message, "Elevation Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Win32Exception ex)
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
            if (txtRelaunchAsAdmin is null)
            {
                return;
            }

            txtRelaunchAsAdmin.Visibility = IsRunningAsAdministrator() || !RequiresElevationForSelectedValidation()
                ? Visibility.Collapsed
                : Visibility.Visible;
        }

        private static bool IsRunningAsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private bool RequiresElevationForSelectedValidation()
        {
            // Self-hosted HTTP-01 always requires binding to port 80 via HttpListener, which needs
            // URL ACL reservation and therefore admin rights on Windows.
            // TLS-ALPN-01 uses a raw TcpListener on port 443, which normally succeeds without
            // elevation, but can be denied on some Windows configurations; surface the prompt as
            // a hint in case the user encounters a port-bind failure.
            return (rbHttp?.IsChecked == true && IsSelectedHttpDeploymentMethod(HttpChallengeDeploymentMethod.SelfHosted))
                || rbTls?.IsChecked == true;
        }

        private void NavPrimaryMenu_ItemInvoked(object sender, RoutedEventArgs e)
        {
            if (_isSyncingNavSelection)
            {
                return;
            }

            if (sender is not Wpf.Ui.Controls.NavigationView nav)
            {
                return;
            }

            Dispatcher.BeginInvoke(new Action(() =>
            {
                if (_isSyncingNavSelection)
                {
                    return;
                }

                if (nav.SelectedItem is FrameworkElement selectedElement && selectedElement.Tag is string pageKey)
                {
                    NavigateToPage(pageKey, pushHistory: true);
                }
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private void NavMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Wpf.Ui.Controls.NavigationViewItem item && item.Tag is string pageKey)
            {
                NavigateToPage(pageKey, pushHistory: true);
            }
        }



        private void NavigateToPage(string pageKey, bool pushHistory)
        {
            if (string.IsNullOrWhiteSpace(pageKey))
            {
                return;
            }

            if (pushHistory && !string.Equals(_currentPageKey, pageKey, StringComparison.Ordinal))
            {
                _navigationHistory.Push(_currentPageKey);
            }

            ShowPage(pageKey);
            _currentPageKey = pageKey;
            SelectMenuForPage(pageKey);
            UpdateBackButtonState();
        }

        private void SelectMenuForPage(string pageKey)
        {
            _isSyncingNavSelection = true;
            try
            {
                NavPrimaryMenu?.Navigate(pageKey);
            }
            catch (InvalidOperationException ex)
            {
                _logger?.LogWarning(ex, "Failed to synchronize navigation menu selection for page key '{PageKey}'.", pageKey);
            }
            catch (ArgumentException ex)
            {
                _logger?.LogWarning(ex, "Failed to synchronize navigation menu selection for page key '{PageKey}'.", pageKey);
            }
            finally
            {
                _isSyncingNavSelection = false;
            }
        }


        private void UpdateBackButtonState()
        {
            if (FindName("btnBack") is Button backButton)
            {
                backButton.IsEnabled = _navigationHistory.Count > 0;
            }
        }

        private void Back_Click(object sender, RoutedEventArgs e)
        {
            if (_navigationHistory.Count == 0)
            {
                return;
            }

            var previousPage = _navigationHistory.Pop();
            NavigateToPage(previousPage, pushHistory: false);
        }

        private void ShowPage(string pageKey)
        {
            if (ManagePage is null || IssuePage is null || SettingsPage is null || LogsPage is null)
            {
                return;
            }

            ManagePage.Visibility = Visibility.Collapsed;
            IssuePage.Visibility = Visibility.Collapsed;
            SettingsPage.Visibility = Visibility.Collapsed;
            LogsPage.Visibility = Visibility.Collapsed;
            FrameworkElement pageToShow;

            switch (pageKey)
            {
                case "Issue":
                    IssuePage.Visibility = Visibility.Visible;
                    pageToShow = IssuePage;
                    SetSectionHeader(
                        "Issue New Certificate",
                        "Create a new certificate with HTTP-01, TLS-ALPN-01, or DNS-01 validation.");
                    break;
                case "Settings":
                    SettingsPage.Visibility = Visibility.Visible;
                    pageToShow = SettingsPage;
                    SetSectionHeader(
                        "Settings",
                        "Manage DNS secrets and application logging preferences.");
                    break;
                case "Logs":
                    LogsPage.Visibility = Visibility.Visible;
                    pageToShow = LogsPage;
                    SetSectionHeader(
                        "Logs",
                        "Inspect activity history, export logs, or clear log files.");
                    break;
                default:
                    ManagePage.Visibility = Visibility.Visible;
                    pageToShow = ManagePage;
                    SetSectionHeader(
                        "Manage Certificates",
                        "Review, renew, revoke, or delete existing local certificates.");
                    break;
            }

            AnimatePage(pageToShow);
        }

        private void SetSectionHeader(string title, string subtitle)
        {
            if (FindName("txtSectionTitle") is TextBlock titleBlock)
            {
                titleBlock.Text = title;
            }

            if (FindName("txtSectionSubtitle") is TextBlock subtitleBlock)
            {
                subtitleBlock.Text = subtitle;
            }
        }

        private static void AnimatePage(UIElement page)
        {
            page.Opacity = 0;

            var fadeIn = new DoubleAnimation
            {
                From = 0,
                To = 1,
                Duration = TimeSpan.FromMilliseconds(170)
            };

            page.BeginAnimation(OpacityProperty, fadeIn);
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
                DeleteCertificateFiles(cert);

                _certificates.Remove(cert);
                CertificateStorage.Save(_certificates);
                LoadCertificatesGrid();
                Log($"🗑 Deleted local certificate for {cert.Domain}");
            }
            catch (IOException ex)
            {
                Log($"❌ Delete failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (UnauthorizedAccessException ex)
            {
                Log($"❌ Delete failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.Security.SecurityException ex)
            {
                Log($"❌ Delete failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Delete Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static void DeleteCertificateFiles(CertificateModel cert)
        {
            if (!string.IsNullOrWhiteSpace(cert.OutputDirectory) && Directory.Exists(cert.OutputDirectory))
            {
                Directory.Delete(cert.OutputDirectory, recursive: true);
                return;
            }

            TryDeleteFile(cert.PfxPath);
            TryDeleteFile(cert.CertificatePemPath);
            TryDeleteFile(cert.ChainPemPath);
            TryDeleteFile(cert.FullChainPemPath);
            TryDeleteFile(cert.PrivateKeyPemPath);
        }

        private static void TryDeleteFile(string path)
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                File.Delete(path);
            }
        }

        private void ValidationMethod_Checked(object sender, RoutedEventArgs e)
        {
            UpdateValidationUiState();
        }

        private void UpdateValidationUiState()
        {
            if (rbDns is null || rbHttp is null || rbTls is null || grpDnsPlugin is null || grpHttpDeployment is null || txtRelaunchAsAdmin is null)
            {
                return;
            }

            var dnsSelected = rbDns.IsChecked == true;
            var httpSelected = rbHttp.IsChecked == true;
            grpDnsPlugin.Visibility = dnsSelected ? Visibility.Visible : Visibility.Collapsed;
            grpHttpDeployment.Visibility = httpSelected ? Visibility.Visible : Visibility.Collapsed;
            txtRelaunchAsAdmin.Visibility = !IsRunningAsAdministrator() && RequiresElevationForSelectedValidation()
                ? Visibility.Visible
                : Visibility.Collapsed;

            UpdateHttpDeploymentUiState();
        }

        private void HttpDeploymentMethod_Changed(object sender, SelectionChangedEventArgs e)
        {
            UpdateHttpDeploymentUiState();
        }

        private void UpdateHttpDeploymentUiState()
        {
            if (pnlHttpTarget is null || pnlHttpCredentials is null || pnlHttpPublicProbe is null || pnlHttpRest is null)
            {
                return;
            }

            var method = GetSelectedHttpDeploymentMethod();

            var usesTarget = method != HttpChallengeDeploymentMethod.SelfHosted;
            var usesCredentials = method == HttpChallengeDeploymentMethod.Ftp ||
                                  method == HttpChallengeDeploymentMethod.Sftp ||
                                  method == HttpChallengeDeploymentMethod.WebDav ||
                                  method == HttpChallengeDeploymentMethod.Rest;
            var usesRestOptions = method == HttpChallengeDeploymentMethod.Rest;
            var usesProbe = method != HttpChallengeDeploymentMethod.SelfHosted;

            pnlHttpTarget.Visibility = usesTarget ? Visibility.Visible : Visibility.Collapsed;
            pnlHttpCredentials.Visibility = usesCredentials ? Visibility.Visible : Visibility.Collapsed;
            pnlHttpRest.Visibility = usesRestOptions ? Visibility.Visible : Visibility.Collapsed;
            pnlHttpPublicProbe.Visibility = usesProbe ? Visibility.Visible : Visibility.Collapsed;

            txtRelaunchAsAdmin.Visibility = !IsRunningAsAdministrator() && RequiresElevationForSelectedValidation()
            ? Visibility.Visible
            : Visibility.Collapsed;
        }

        private HttpChallengeDeploymentOptions? BuildHttpDeploymentOptions(ChallengeValidationMethod validationMethod)
        {
            if (validationMethod != ChallengeValidationMethod.Http01)
            {
                return null;
            }

            var method = GetSelectedHttpDeploymentMethod();
            var target = txtHttpTarget?.Text?.Trim() ?? string.Empty;
            var username = txtHttpUsername?.Text?.Trim() ?? string.Empty;
            var password = txtHttpPassword?.Password?.Trim() ?? string.Empty;
            var publicProbeTemplate = txtHttpPublicProbeTemplate?.Text?.Trim() ?? string.Empty;

            if (method != HttpChallengeDeploymentMethod.SelfHosted && string.IsNullOrWhiteSpace(target))
            {
                throw new InvalidOperationException("HTTP-01 target is required for the selected deployment method.");
            }

            return new HttpChallengeDeploymentOptions
            {
                Method = method,
                Target = target,
                Username = username,
                Password = password,
                PublicValidationUrlTemplate = string.IsNullOrWhiteSpace(publicProbeTemplate)
                    ? "http://{domain}/.well-known/acme-challenge/{token}"
                    : publicProbeTemplate,
                RestMethod = txtHttpRestMethod?.Text?.Trim() ?? "POST",
                AdditionalHeaderName = txtHttpHeaderName?.Text?.Trim() ?? string.Empty,
                AdditionalHeaderValue = txtHttpHeaderValue?.Text?.Trim() ?? string.Empty,
                BearerToken = txtHttpBearerToken?.Text?.Trim() ?? string.Empty,
                SkipTlsCertificateValidation = chkHttpSkipTlsValidation?.IsChecked == true
            };
        }

        private HttpChallengeDeploymentMethod GetSelectedHttpDeploymentMethod()
        {
            if (cmbHttpDeploymentMethod?.SelectedItem is ComboBoxItem item && item.Tag is string raw)
            {
                return AcmeService.ParseHttpDeploymentMethod(raw);
            }

            return HttpChallengeDeploymentMethod.SelfHosted;
        }

        private bool IsSelectedHttpDeploymentMethod(HttpChallengeDeploymentMethod expected)
        {
            return GetSelectedHttpDeploymentMethod() == expected;
        }

        private string ResolveAcmeDirectoryUrl()
        {
            var customUrl = txtCustomAcmeDirectoryUrl?.Text?.Trim() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(customUrl))
            {
                if (!Uri.TryCreate(customUrl, UriKind.Absolute, out var customUri) ||
                    (customUri.Scheme != Uri.UriSchemeHttps && customUri.Scheme != Uri.UriSchemeHttp))
                {
                    throw new InvalidOperationException("Custom ACME directory URL must be a valid absolute HTTP/HTTPS URL.");
                }

                return customUri.ToString();
            }

            var useStaging = chkUseStaging?.IsChecked == true;
            return useStaging
                ? AcmeService.LetsEncryptStagingDirectoryUrl
                : AcmeService.LetsEncryptProductionDirectoryUrl;
        }

        private static string GetDnsSecretDomainContext(IReadOnlyList<string> domains)
        {
            if (domains.Count == 0)
            {
                return string.Empty;
            }

            var firstDomain = domains[0].Trim();
            if (string.IsNullOrWhiteSpace(firstDomain))
            {
                return string.Empty;
            }

            return firstDomain.StartsWith("*.", StringComparison.Ordinal)
                ? firstDomain[2..]
                : firstDomain;
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
                var selectLabel = new System.Windows.Controls.TextBlock
                {
                    Text = "Stored Credentials",
                    Margin = new Thickness(0, 4, 0, 2),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold
                };
                pnlDnsFields.Children.Add(selectLabel);

                var credentialCombo = new System.Windows.Controls.ComboBox
                {
                    Height = 34,
                    Margin = new Thickness(0, 0, 0, 12)
                };
                credentialCombo.ItemContainerStyle = (Style)FindResource("ReadableComboBoxItemStyle");

                credentialCombo.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = "(use new/custom credentials)" });

                foreach (var cred in allCredentials)
                {
                    var displayName = string.IsNullOrEmpty(cred.Domain) ? "(default)" : cred.Domain;
                    credentialCombo.Items.Add(new System.Windows.Controls.ComboBoxItem { Content = displayName, Tag = cred });
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
                var label = new System.Windows.Controls.TextBlock
                {
                    Text = field.IsRequired ? $"{field.Label} *" : field.Label,
                    Margin = new Thickness(0, 4, 0, 2),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold
                };
                pnlDnsFields.Children.Add(label);

                var input = new System.Windows.Controls.TextBox
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
                    pnlDnsFields.Children.Add(new System.Windows.Controls.TextBlock
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
            foreach (var field in plugin.Instance.GetCredentialFields().Where(field => _dnsFieldInputs.ContainsKey(field.Name)))
            {
                var input = _dnsFieldInputs[field.Name];
                input.Text = credentials.TryGetValue(field.Name, out var value)
                    ? value
                    : string.Empty;
            }
        }

        private void ClearDnsFields(LoadedDnsPlugin plugin)
        {
            foreach (var field in plugin.Instance.GetCredentialFields().Where(field => _dnsFieldInputs.ContainsKey(field.Name)))
            {
                _dnsFieldInputs[field.Name].Text = string.Empty;
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
            catch (InvalidOperationException ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (HttpRequestException ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (TaskCanceledException ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                Log($"❌ Revoke failed: {ex.Message}");
                MessageBox.Show(ex.Message, "Revoke Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ViewDnsSecrets_Click(object sender, RoutedEventArgs e)
        {
            try
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
            catch (Exception ex)
            {
                Log($"❌ Failed to open stored DNS secrets: {ex.Message}");
                MessageBox.Show($"Unable to open stored DNS secrets.\n\n{ex.Message}", "Stored DNS Secrets", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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

        private void AppearanceTheme_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (cmbAppearanceTheme?.SelectedItem is not ComboBoxItem selectedItem || selectedItem.Tag is not string themePreference)
            {
                return;
            }

            var app = (App)Application.Current;
            app.SetThemePreference(themePreference);
            Log($"🎨 Application theme changed to {themePreference}");
        }

        private void SetAppearanceThemeSelection(string themePreference)
        {
            if (cmbAppearanceTheme is null)
            {
                return;
            }

            foreach (var item in cmbAppearanceTheme.Items
                .OfType<ComboBoxItem>()
                .Where(item => item.Tag is string tag &&
                    string.Equals(tag, themePreference, StringComparison.OrdinalIgnoreCase)))
            {
                cmbAppearanceTheme.SelectedItem = item;
                return;
            }

            cmbAppearanceTheme.SelectedIndex = 0;
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
                    catch (IOException)
                    {
                        // Skip if we can't read
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Skip if we can't read
                    }
                    catch (System.Security.SecurityException)
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
            catch (IOException)
            {
                // Silently fail if we can't load persisted logs
            }
            catch (UnauthorizedAccessException)
            {
                // Silently fail if we can't load persisted logs
            }
            catch (System.Security.SecurityException)
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
            catch (IOException)
            {
                // Silently fail
            }
            catch (UnauthorizedAccessException)
            {
                // Silently fail
            }
            catch (ObjectDisposedException)
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
            catch (InvalidOperationException ex)
            {
                Log($"❌ Failed to export logs: {ex.Message}");
                MessageBox.Show($"Failed to export logs: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                Log($"❌ Failed to export logs: {ex.Message}");
                MessageBox.Show($"Failed to export logs: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (UnauthorizedAccessException ex)
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
            catch (InvalidOperationException ex)
            {
                Log($"❌ Failed to clear logs: {ex.Message}");
                MessageBox.Show($"Failed to clear logs: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (IOException ex)
            {
                Log($"❌ Failed to clear logs: {ex.Message}");
                MessageBox.Show($"Failed to clear logs: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (UnauthorizedAccessException ex)
            {
                Log($"❌ Failed to clear logs: {ex.Message}");
                MessageBox.Show($"Failed to clear logs: {ex.Message}", "Clear Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
