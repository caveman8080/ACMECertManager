using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;
using MessageBoxResult = System.Windows.MessageBoxResult;

namespace ACMECertManager
{
    public partial class DnsSecretsWindow : Wpf.Ui.Controls.FluentWindow
    {
        private readonly List<LoadedDnsPlugin> _availablePlugins;
        private readonly Dictionary<string, IReadOnlyList<DnsCredentialField>> _pluginFields;
        private string _selectedPluginId = string.Empty;
        private bool _revealHttpSecrets;

        public DnsSecretsWindow(List<LoadedDnsPlugin> availablePlugins, Dictionary<string, IReadOnlyList<DnsCredentialField>> pluginFields)
        {
            InitializeComponent();
            _availablePlugins = availablePlugins;
            _pluginFields = pluginFields;
            LoadPluginList();
        }

        private void LoadPluginList()
        {
            var previous = lstPlugins.SelectedItem as SecretSourceItem;
            lstPlugins.Items.Clear();
            var allSecrets = DnsSecretStorage.LoadAll();

            foreach (var entry in allSecrets
                .Where(entry => entry.Credentials is { Count: > 0 })
                .OrderBy(entry => entry.PluginId, StringComparer.OrdinalIgnoreCase))
            {
                lstPlugins.Items.Add(new SecretSourceItem
                {
                    PluginId = entry.PluginId,
                    Label = entry.PluginId
                });
            }

            if (HttpUploadCredentialStore.List(CertificateStorage.Load()).Count > 0)
            {
                lstPlugins.Items.Add(SecretSourceItem.HttpUploads());
            }

            if (lstPlugins.Items.Count == 0)
            {
                ShowEmptySelection();
                return;
            }

            var match = lstPlugins.Items.OfType<SecretSourceItem>().FirstOrDefault(item =>
                previous is not null && item.IsHttpUpload == previous.IsHttpUpload &&
                string.Equals(item.PluginId, previous.PluginId, StringComparison.OrdinalIgnoreCase));
            lstPlugins.SelectedItem = match ?? lstPlugins.Items[0];
        }

        private void PluginList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lstPlugins.SelectedItem is not SecretSourceItem source)
            {
                ShowEmptySelection();
                return;
            }

            if (source.IsHttpUpload)
            {
                ShowHttpCredentials();
                return;
            }

            ShowDnsCredentials(source.PluginId ?? string.Empty);
        }

        private void ShowEmptySelection()
        {
            _selectedPluginId = string.Empty;
            dgSecrets.ItemsSource = null;
            dgHttpCredentials.ItemsSource = null;
            dgSecrets.Visibility = Visibility.Visible;
            dgHttpCredentials.Visibility = Visibility.Collapsed;
            txtSelectedPlugin.Text = "Select a source";
            txtCredentialHint.Text = "Stored credentials for the selected source appear below.";
            btnAdd.Visibility = Visibility.Collapsed;
            btnDelete.Visibility = Visibility.Collapsed;
            chkRevealHttpSecrets.Visibility = Visibility.Collapsed;
        }

        private void ShowDnsCredentials(string pluginId)
        {
            _selectedPluginId = pluginId;
            dgHttpCredentials.Visibility = Visibility.Collapsed;
            dgHttpCredentials.ItemsSource = null;
            dgSecrets.Visibility = Visibility.Visible;
            chkRevealHttpSecrets.Visibility = Visibility.Collapsed;
            btnAdd.Visibility = Visibility.Visible;
            btnDelete.Visibility = Visibility.Visible;
            txtSelectedPlugin.Text = string.IsNullOrEmpty(pluginId) ? "Select a plugin" : $"Plugin: {pluginId}";
            txtCredentialHint.Text = "Stored credentials for the selected plugin appear below.";

            var credentials = DnsSecretStorage.GetCredentialsForPlugin(pluginId);
            dgSecrets.ItemsSource = credentials.Select(c => new CredentialDisplayItem
            {
                Domain = string.IsNullOrEmpty(c.Domain) ? "(default)" : c.Domain,
                Values = c.Values,
                OriginalDomain = c.Domain
            }).ToList();
        }

        private void ShowHttpCredentials()
        {
            _selectedPluginId = string.Empty;
            dgSecrets.Visibility = Visibility.Collapsed;
            dgSecrets.ItemsSource = null;
            dgHttpCredentials.Visibility = Visibility.Visible;
            chkRevealHttpSecrets.Visibility = Visibility.Visible;
            btnAdd.Visibility = Visibility.Collapsed;
            btnDelete.Visibility = Visibility.Collapsed;
            txtSelectedPlugin.Text = "HTTP upload credentials";
            txtCredentialHint.Text = "Saved with each certificate and reused on renewal. Reveal to view passwords and tokens.";
            BindHttpCredentials();
        }

        private void BindHttpCredentials()
        {
            var revealed = _revealHttpSecrets;
            dgHttpCredentials.ItemsSource = HttpUploadCredentialStore.List(CertificateStorage.Load())
                .Select(record => new HttpCredentialDisplayItem
                {
                    Record = record,
                    Domain = string.IsNullOrWhiteSpace(record.Domain) ? "(unnamed certificate)" : record.Domain,
                    Target = record.Target,
                    Port = record.Port?.ToString() ?? string.Empty,
                    Username = record.Username,
                    Password = HttpUploadCredentialStore.Mask(record.Password, revealed),
                    BearerToken = HttpUploadCredentialStore.Mask(record.BearerToken, revealed),
                    AdditionalHeaderValue = HttpUploadCredentialStore.Mask(record.AdditionalHeaderValue, revealed)
                })
                .ToList();
        }

        private void RevealHttpSecrets_Changed(object sender, RoutedEventArgs e)
        {
            _revealHttpSecrets = chkRevealHttpSecrets.IsChecked == true;
            if (dgHttpCredentials.Visibility == Visibility.Visible)
            {
                var selected = dgHttpCredentials.SelectedItem as HttpCredentialDisplayItem;
                BindHttpCredentials();
                if (selected is not null)
                {
                    dgHttpCredentials.SelectedItem = dgHttpCredentials.Items
                        .OfType<HttpCredentialDisplayItem>()
                        .FirstOrDefault(item => SameHttpRecord(item.Record, selected.Record));
                }
            }
        }

        private void Edit_Click(object sender, RoutedEventArgs e)
        {
            if (lstPlugins.SelectedItem is SecretSourceItem { IsHttpUpload: true })
            {
                EditHttpCredential();
                return;
            }

            if (string.IsNullOrEmpty(_selectedPluginId) || dgSecrets.SelectedItem is not CredentialDisplayItem item)
            {
                MessageBox.Show("Please select a credential to edit.", "Select Credential", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var plugin = _availablePlugins.FirstOrDefault(p => p.Metadata.Id == _selectedPluginId);
            if (plugin == null)
            {
                MessageBox.Show("Plugin not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var editWindow = new DnsSecretEditWindow(
                plugin,
                item.Values,
                item.OriginalDomain,
                _pluginFields.TryGetValue(_selectedPluginId, out var fields) ? fields : new List<DnsCredentialField>());

            if (editWindow.ShowDialog() == true)
            {
                var updatedCred = new DnsSecretCredential
                {
                    Domain = editWindow.Domain,
                    Values = editWindow.Credentials
                };

                if (editWindow.Domain != item.OriginalDomain)
                {
                    DnsSecretStorage.DeleteCredential(_selectedPluginId, item.OriginalDomain);
                }

                DnsSecretStorage.SaveCredential(_selectedPluginId, updatedCred);
                ShowDnsCredentials(_selectedPluginId);
            }
        }

        private void EditHttpCredential()
        {
            if (dgHttpCredentials.SelectedItem is not HttpCredentialDisplayItem item)
            {
                MessageBox.Show("Please select an HTTP upload credential to edit.", "Select Credential", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var editWindow = new HttpUploadCredentialEditWindow(item.Record)
            {
                Owner = this
            };

            if (editWindow.ShowDialog() == true)
            {
                BindHttpCredentials();
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (lstPlugins.SelectedItem is SecretSourceItem { IsHttpUpload: true })
            {
                return;
            }

            if (string.IsNullOrEmpty(_selectedPluginId) || dgSecrets.SelectedItem is not CredentialDisplayItem item)
            {
                MessageBox.Show("Please select a credential to delete.", "Select Credential", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var confirmed = MessageBox.Show(
                $"Delete credentials for domain '{item.Domain}'?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (confirmed == MessageBoxResult.Yes)
            {
                DnsSecretStorage.DeleteCredential(_selectedPluginId, item.OriginalDomain);
                if (DnsSecretStorage.GetCredentialsForPlugin(_selectedPluginId).Count == 0)
                {
                    LoadPluginList();
                }
                else
                {
                    ShowDnsCredentials(_selectedPluginId);
                }
            }
        }

        private void Add_Click(object sender, RoutedEventArgs e)
        {
            if (lstPlugins.SelectedItem is SecretSourceItem { IsHttpUpload: true } || string.IsNullOrEmpty(_selectedPluginId))
            {
                MessageBox.Show("Please select a plugin first.", "Select Plugin", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var plugin = _availablePlugins.FirstOrDefault(p => p.Metadata.Id == _selectedPluginId);
            if (plugin == null)
            {
                MessageBox.Show("Plugin not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var editWindow = new DnsSecretEditWindow(
                plugin,
                new Dictionary<string, string>(),
                string.Empty,
                _pluginFields.TryGetValue(_selectedPluginId, out var fields) ? fields : new List<DnsCredentialField>());

            if (editWindow.ShowDialog() == true)
            {
                var newCred = new DnsSecretCredential
                {
                    Domain = editWindow.Domain,
                    Values = editWindow.Credentials
                };

                DnsSecretStorage.SaveCredential(_selectedPluginId, newCred);
                ShowDnsCredentials(_selectedPluginId);
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private static bool SameHttpRecord(HttpUploadCredentialRecord left, HttpUploadCredentialRecord right)
        {
            if (!string.IsNullOrWhiteSpace(left.OutputDirectory) || !string.IsNullOrWhiteSpace(right.OutputDirectory))
            {
                return string.Equals(left.OutputDirectory, right.OutputDirectory, StringComparison.OrdinalIgnoreCase);
            }

            return string.Equals(left.Domain, right.Domain, StringComparison.OrdinalIgnoreCase)
                && string.Equals(left.DeploymentMethod, right.DeploymentMethod, StringComparison.OrdinalIgnoreCase);
        }

        private sealed class SecretSourceItem
        {
            public string? PluginId { get; init; }
            public bool IsHttpUpload { get; init; }
            public string Label { get; init; } = string.Empty;

            public static SecretSourceItem HttpUploads()
            {
                return new SecretSourceItem
                {
                    IsHttpUpload = true,
                    Label = "HTTP upload credentials"
                };
            }

            public override string ToString() => Label;
        }

        public sealed class CredentialDisplayItem
        {
            public string Domain { get; set; } = string.Empty;
            public string OriginalDomain { get; set; } = string.Empty;
            public Dictionary<string, string> Values { get; set; } = new();

            public string CredentialSummary
            {
                get
                {
                    var keys = Values.Keys.Where(k => !k.Equals("propagationSeconds", StringComparison.OrdinalIgnoreCase)).ToList();
                    return keys.Count == 0 ? "(empty)" : string.Join(", ", keys);
                }
            }
        }

        public sealed class HttpCredentialDisplayItem
        {
            public HttpUploadCredentialRecord Record { get; init; } = new();
            public string Domain { get; init; } = string.Empty;
            public string Target { get; init; } = string.Empty;
            public string Port { get; init; } = string.Empty;
            public string Username { get; init; } = string.Empty;
            public string Password { get; init; } = string.Empty;
            public string BearerToken { get; init; } = string.Empty;
            public string AdditionalHeaderValue { get; init; } = string.Empty;
        }
    }
}
