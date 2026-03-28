using System;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace ACMECertManager
{
    public enum AppTheme
    {
        Light,
        Dark
    }

    public partial class App : Application
    {
        public AppTheme CurrentTheme { get; private set; } = AppTheme.Light;
        public bool SavePemChainArtifacts { get; private set; }
        public int MaxLogFileSizeMb { get; private set; } = 10;

        protected override void OnStartup(StartupEventArgs e)
        {
            RuntimePaths.EnsureRequiredDirectories();
            RuntimePaths.MigrateLegacyFiles();

            var settings = LoadPersistedSettings();
            SavePemChainArtifacts = settings.SavePemChainArtifacts;
            MaxLogFileSizeMb = settings.MaxLogFileSizeMb;
            ApplyTheme(settings.Theme);
            base.OnStartup(e);
        }

        public void ApplyTheme(AppTheme theme)
        {
            CurrentTheme = theme;

            if (theme == AppTheme.Dark)
            {
                SetBrush("WindowBackgroundBrush", "#111827");
                SetBrush("SurfaceBrush", "#1F2937");
                SetBrush("SurfaceAltBrush", "#374151");
                SetBrush("PrimaryTextBrush", "#F9FAFB");
                SetBrush("SecondaryTextBrush", "#D1D5DB");
                SetBrush("SuccessBrush", "#34D399");
                SetBrush("WarningBrush", "#F87171");
                SetBrush("BorderBrush", "#4B5563");
                SetBrush("LogBackgroundBrush", "#0B1220");
                SetBrush("LogTextBrush", "#86EFAC");
            }
            else
            {
                SetBrush("WindowBackgroundBrush", "#F5F5F5");
                SetBrush("SurfaceBrush", "#FFFFFF");
                SetBrush("SurfaceAltBrush", "#F0F0F0");
                SetBrush("PrimaryTextBrush", "#1F2937");
                SetBrush("SecondaryTextBrush", "#4B5563");
                SetBrush("SuccessBrush", "#198754");
                SetBrush("WarningBrush", "#D13438");
                SetBrush("BorderBrush", "#D0D7DE");
                SetBrush("LogBackgroundBrush", "#1E1E1E");
                SetBrush("LogTextBrush", "#00FF00");
            }

            SaveSettings();
        }

        public void SetSavePemChainArtifacts(bool enabled)
        {
            SavePemChainArtifacts = enabled;
            SaveSettings();
        }

        public void SetMaxLogFileSizeMb(int sizeMb)
        {
            if (sizeMb > 0)
            {
                MaxLogFileSizeMb = sizeMb;
                SaveSettings();
            }
        }

        private void SetBrush(string resourceKey, string hexColor)
        {
            Resources[resourceKey] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hexColor));
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
            catch
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
                    Theme = CurrentTheme,
                    SavePemChainArtifacts = SavePemChainArtifacts,
                    MaxLogFileSizeMb = MaxLogFileSizeMb
                };
                var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(RuntimePaths.ThemeSettingsFile, json);
            }
            catch
            {
                // Keep running even if theme settings cannot be written.
            }
        }

        private sealed class ThemeSettings
        {
            public AppTheme Theme { get; set; } = AppTheme.Light;
            public bool SavePemChainArtifacts { get; set; }
            public int MaxLogFileSizeMb { get; set; } = 10;
        }
    }
}
