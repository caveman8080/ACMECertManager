using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace ACMECertManager
{
    public partial class DnsSecretEditWindow : Window
    {
        private readonly Dictionary<string, TextBox> _credentialInputs = new(StringComparer.OrdinalIgnoreCase);
        private readonly LoadedDnsPlugin _plugin;
        private readonly IReadOnlyList<DnsCredentialField> _fields;

        public string Domain { get; private set; } = string.Empty;
        public Dictionary<string, string> Credentials { get; private set; } = new();

        public DnsSecretEditWindow(
            LoadedDnsPlugin plugin,
            IReadOnlyDictionary<string, string> existingCredentials,
            string existingDomain,
            IReadOnlyList<DnsCredentialField> fields)
        {
            InitializeComponent();
            _plugin = plugin;
            _fields = fields;
            Domain = existingDomain;
            Credentials = new Dictionary<string, string>(existingCredentials);

            InitializeUI(existingCredentials, existingDomain);
        }

        private void InitializeUI(IReadOnlyDictionary<string, string> existingCredentials, string existingDomain)
        {
            txtPluginName.Text = _plugin.Metadata.DisplayName;
            txtPluginDescription.Text = _plugin.Metadata.Description;
            txtDomain.Text = existingDomain;

            foreach (var field in _fields)
            {
                var label = new TextBlock
                {
                    Text = field.IsRequired ? $"{field.Label} *" : field.Label,
                    Margin = new Thickness(0, 12, 0, 5),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("TextBrush")
                };
                pnlCredentialFields.Children.Add(label);

                var input = new TextBox
                {
                    Height = 34,
                    Padding = new Thickness(10, 7, 10, 7),
                    FontSize = 12,
                    Background = (Brush)FindResource("InputBackgroundBrush"),
                    Foreground = (Brush)FindResource("TextBrush"),
                    BorderBrush = (Brush)FindResource("BorderBrush"),
                    ToolTip = field.Placeholder
                };

                if (field.IsSecret)
                {
                    // For secret fields, use a PasswordBox alternative via TextBox with masked text
                    // Note: In a production app, you'd use a proper PasswordBox
                }

                if (existingCredentials.TryGetValue(field.Name, out var value))
                {
                    input.Text = value;
                }

                _credentialInputs[field.Name] = input;
                pnlCredentialFields.Children.Add(input);

                if (!string.IsNullOrWhiteSpace(field.Placeholder))
                {
                    pnlCredentialFields.Children.Add(new TextBlock
                    {
                        Text = field.Placeholder,
                        Margin = new Thickness(0, 3, 0, 0),
                        FontSize = 11,
                        Foreground = (Brush)FindResource("SecondaryTextBrush")
                    });
                }
            }
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Validate required fields
                foreach (var field in _fields)
                {
                    if (!_credentialInputs.TryGetValue(field.Name, out var input))
                    {
                        throw new InvalidOperationException($"Missing input for '{field.Label}'.");
                    }

                    var value = input.Text?.Trim() ?? string.Empty;
                    if (field.IsRequired && string.IsNullOrWhiteSpace(value))
                    {
                        throw new InvalidOperationException($"'{field.Label}' is required.");
                    }
                }

                Domain = txtDomain.Text?.Trim() ?? string.Empty;

                // Collect credentials
                Credentials.Clear();
                foreach (var field in _fields)
                {
                    if (_credentialInputs.TryGetValue(field.Name, out var input))
                    {
                        var value = input.Text?.Trim() ?? string.Empty;
                        if (!string.IsNullOrEmpty(value))
                        {
                            Credentials[field.Name] = value;
                        }
                    }
                }

                DialogResult = true;
                Close();
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.Show(ex.Message, "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
