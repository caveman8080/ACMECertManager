using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TextBox = System.Windows.Controls.TextBox;
using TextBlock = System.Windows.Controls.TextBlock;
using MessageBox = System.Windows.MessageBox;
using MessageBoxButton = System.Windows.MessageBoxButton;
using MessageBoxImage = System.Windows.MessageBoxImage;

namespace ACMECertManager
{
    public partial class DnsSecretEditWindow : Wpf.Ui.Controls.FluentWindow
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

            var textBrush = GetBrushResource("TextBrush", SystemColors.WindowTextBrush);
            var secondaryTextBrush = GetBrushResource("SecondaryTextBrush", SystemColors.GrayTextBrush);
            var inputBackgroundBrush = GetBrushResource("InputBackgroundBrush", SystemColors.WindowBrush);
            var borderBrush = GetBrushResource("BorderBrush", SystemColors.ActiveBorderBrush);

            foreach (var field in _fields)
            {
                var label = new TextBlock
                {
                    Text = field.IsRequired ? $"{field.Label} *" : field.Label,
                    Margin = new Thickness(0, 14, 0, 6),
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = TryFindResource("TextFillColorPrimaryBrush") as Brush ?? textBrush
                };
                pnlCredentialFields.Children.Add(label);

                // Keep System.Windows.Controls.TextBox for dynamic fields so existing
                // Text/Password-style handling and dictionary typing stay simple.
                var input = new TextBox
                {
                    MinHeight = 34,
                    Padding = new Thickness(10, 7, 10, 7),
                    FontSize = 13,
                    Background = inputBackgroundBrush,
                    Foreground = textBrush,
                    BorderBrush = borderBrush,
                    ToolTip = field.Placeholder
                };

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
                        Margin = new Thickness(0, 4, 0, 0),
                        FontSize = 11,
                        Foreground = TryFindResource("TextFillColorSecondaryBrush") as Brush ?? secondaryTextBrush
                    });
                }
            }
        }

        private Brush GetBrushResource(string key, Brush fallback)
        {
            return TryFindResource(key) as Brush ?? fallback;
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
                foreach (var field in _fields.Where(field => _credentialInputs.ContainsKey(field.Name)))
                {
                    var input = _credentialInputs[field.Name];
                    var value = input.Text?.Trim() ?? string.Empty;
                    if (!string.IsNullOrEmpty(value))
                    {
                        Credentials[field.Name] = value;
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
