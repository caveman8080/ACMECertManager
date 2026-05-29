using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

namespace ACMECertManager
{
    public partial class DnsSecretsWindow : Window
    {
        private readonly List<LoadedDnsPlugin> _availablePlugins;
        private readonly Dictionary<string, IReadOnlyList<DnsCredentialField>> _pluginFields;
        private string _selectedPluginId = string.Empty;

        public DnsSecretsWindow(List<LoadedDnsPlugin> availablePlugins, Dictionary<string, IReadOnlyList<DnsCredentialField>> pluginFields)
        {
            InitializeComponent();
            _availablePlugins = availablePlugins;
            _pluginFields = pluginFields;
            LoadPluginList();
        }

        private void LoadPluginList()
        {
            lstPlugins.Items.Clear();
            var allSecrets = DnsSecretStorage.LoadAll();

            foreach (var entry in allSecrets
                .Where(entry => entry.Credentials.Count > 0)
                .OrderBy(entry => entry.PluginId, StringComparer.OrdinalIgnoreCase))
            {
                lstPlugins.Items.Add(entry.PluginId);
            }

            if (lstPlugins.Items.Count > 0)
            {
                lstPlugins.SelectedIndex = 0;
            }
        }

        private void PluginList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            dgSecrets.ItemsSource = null;
            _selectedPluginId = lstPlugins.SelectedItem as string ?? string.Empty;

            if (string.IsNullOrEmpty(_selectedPluginId))
            {
                txtSelectedPlugin.Text = "Select a plugin";
                return;
            }

            txtSelectedPlugin.Text = $"Plugin: {_selectedPluginId}";

            var credentials = DnsSecretStorage.GetCredentialsForPlugin(_selectedPluginId);
            var displayItems = credentials.Select(c => new CredentialDisplayItem
            {
                Domain = string.IsNullOrEmpty(c.Domain) ? "(default)" : c.Domain,
                Values = c.Values,
                OriginalDomain = c.Domain
            }).ToList();

            dgSecrets.ItemsSource = displayItems;
        }

        private void Edit_Click(object sender, RoutedEventArgs e)
        {
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

                // Delete old credential if domain changed
                if (editWindow.Domain != item.OriginalDomain)
                {
                    DnsSecretStorage.DeleteCredential(_selectedPluginId, item.OriginalDomain);
                }

                DnsSecretStorage.SaveCredential(_selectedPluginId, updatedCred);

                // Refresh display
                PluginList_SelectionChanged(null!, null!);
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
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
                PluginList_SelectionChanged(null!, null!);

                // If no more credentials for this plugin, remove from list
                if (DnsSecretStorage.GetCredentialsForPlugin(_selectedPluginId).Count == 0)
                {
                    LoadPluginList();
                }
            }
        }

        private void Add_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_selectedPluginId))
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

                // Refresh display
                PluginList_SelectionChanged(null!, null!);
            }
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
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
    }
}
