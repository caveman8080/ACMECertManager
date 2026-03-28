using System;
using System.IO;
using System.Text.Json;
using System.Windows;

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
            base.OnStartup(e);
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
            public string? Theme { get; set; }
            public int MaxLogFileSizeMb { get; set; } = 10;
        }
    }
}
