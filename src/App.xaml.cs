using System;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace ACMECertManager
{
    public partial class App : Application
    {
        public int MaxLogFileSizeMb { get; private set; } = 10;

        protected override void OnStartup(StartupEventArgs e)
        {
            RuntimePaths.EnsureRequiredDirectories();
            RuntimePaths.MigrateLegacyFiles();

            var settings = LoadPersistedSettings();
            MaxLogFileSizeMb = settings.MaxLogFileSizeMb;
            ApplySystemThemeBrushes();
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            base.OnExit(e);
        }

        private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category is UserPreferenceCategory.Color or UserPreferenceCategory.General or UserPreferenceCategory.VisualStyle)
            {
                Dispatcher.Invoke(ApplySystemThemeBrushes);
            }
        }

        private void ApplySystemThemeBrushes()
        {
            var darkMode = IsSystemDarkModeEnabled();

            if (darkMode)
            {
                SetBrush("WindowBackgroundBrush", 0x18, 0x18, 0x18);
                SetBrush("SurfaceBrush", 0x20, 0x20, 0x20);
                SetBrush("InputBackgroundBrush", 0x2A, 0x2A, 0x2A);
                SetBrush("PrimaryTextBrush", 0xF7, 0xF7, 0xF7);
                SetBrush("TextBrush", 0xF7, 0xF7, 0xF7);
                SetBrush("SecondaryTextBrush", 0xC9, 0xC9, 0xC9);
                SetBrush("BorderBrush", 0x4A, 0x4A, 0x4A);
                SetBrush("SecondaryBrush", 0x30, 0x30, 0x30);
                SetBrush("NavSelectedBrush", 0x36, 0x8E, 0xF0, 0.28);
                SetBrush("NavHoverBrush", 0xFF, 0xFF, 0xFF, 0.10);
                SetBrush("NavSelectedBorderBrush", 0x5A, 0xA6, 0xF6, 0.92);
            }
            else
            {
                SetBrush("WindowBackgroundBrush", 0xF6, 0xF6, 0xF6);
                SetBrush("SurfaceBrush", 0xFF, 0xFF, 0xFF);
                SetBrush("InputBackgroundBrush", 0xFF, 0xFF, 0xFF);
                SetBrush("PrimaryTextBrush", 0x20, 0x20, 0x20);
                SetBrush("TextBrush", 0x20, 0x20, 0x20);
                SetBrush("SecondaryTextBrush", 0x62, 0x62, 0x62);
                SetBrush("BorderBrush", 0xCC, 0xCC, 0xCC);
                SetBrush("SecondaryBrush", 0xF2, 0xF2, 0xF2);
                SetBrush("NavSelectedBrush", 0x1A, 0x73, 0xE8, 0.14);
                SetBrush("NavHoverBrush", 0x00, 0x00, 0x00, 0.06);
                SetBrush("NavSelectedBorderBrush", 0x1A, 0x73, 0xE8, 0.7);
            }
        }

        private void SetBrush(string resourceKey, byte red, byte green, byte blue, double opacity = 1.0)
        {
            Resources[resourceKey] = new SolidColorBrush(Color.FromRgb(red, green, blue)) { Opacity = opacity };
        }

        private static bool IsSystemDarkModeEnabled()
        {
            try
            {
                const string personalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
                using var key = Registry.CurrentUser.OpenSubKey(personalizeKey);
                var value = key?.GetValue("AppsUseLightTheme");

                if (value is int intValue)
                {
                    return intValue == 0;
                }

                return false;
            }
            catch (System.Security.SecurityException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }

        public void SetMaxLogFileSizeMb(int sizeMb)
        {
            if (sizeMb > 0)
            {
                MaxLogFileSizeMb = sizeMb;
                SaveSettings();
            }
        }

        private ThemeSettings LoadPersistedSettings()
        {
            try
            {
                if (!File.Exists(RuntimePaths.ThemeSettingsFile))
                    return new ThemeSettings();

                var json = File.ReadAllText(RuntimePaths.ThemeSettingsFile);
                var settings = JsonSerializer.Deserialize<ThemeSettings>(json);
                if (settings is null)
                    return new ThemeSettings();

                return settings;
            }
            catch (IOException)
            {
                return new ThemeSettings();
            }
            catch (JsonException)
            {
                return new ThemeSettings();
            }
            catch (UnauthorizedAccessException)
            {
                return new ThemeSettings();
            }
            catch (System.Security.SecurityException)
            {
                return new ThemeSettings();
            }
        }

        private void SaveSettings()
        {
            try
            {
                var settings = new ThemeSettings
                {
                    MaxLogFileSizeMb = MaxLogFileSizeMb
                };
                var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(RuntimePaths.ThemeSettingsFile, json);
            }
            catch (IOException)
            {
                // Keep running even if theme settings cannot be written.
            }
            catch (UnauthorizedAccessException)
            {
                // Keep running even if theme settings cannot be written.
            }
            catch (System.Security.SecurityException)
            {
                // Keep running even if theme settings cannot be written.
            }
        }

        private sealed class ThemeSettings
        {
            public string? Theme { get; set; }
            public int MaxLogFileSizeMb { get; set; } = 10;
        }
    }
}
