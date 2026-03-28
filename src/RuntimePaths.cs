using System;
using System.Collections.Generic;
using System.IO;

namespace ACMECertManager
{
    internal static class RuntimePaths
    {
        public static string BaseDirectory => AppContext.BaseDirectory;
        public static string PluginsDirectory => Path.Combine(BaseDirectory, "plugins");
        public static string LogsDirectory => Path.Combine(BaseDirectory, "logs");
        public static string CertsDirectory => Path.Combine(BaseDirectory, "certs");
        public static string StorageDirectory => Path.Combine(BaseDirectory, "storage");

        public static string LogFile => Path.Combine(LogsDirectory, "acm.log");
        public static string AccountFile => Path.Combine(StorageDirectory, "acme-account.json");
        public static string CertificatesFile => Path.Combine(StorageDirectory, "certificates.json");
        public static string ThemeSettingsFile => Path.Combine(StorageDirectory, "ui-settings.json");
        public static string DnsSecretsFile => Path.Combine(StorageDirectory, "dns-secrets.json");

        public static void EnsureRequiredDirectories()
        {
            Directory.CreateDirectory(PluginsDirectory);
            Directory.CreateDirectory(LogsDirectory);
            Directory.CreateDirectory(CertsDirectory);
            Directory.CreateDirectory(StorageDirectory);
        }

        public static IReadOnlyList<string> MigrateLegacyFiles()
        {
            var migrated = new List<string>();

            TryMigrateLegacyFile("acme-account.json", AccountFile, migrated);
            TryMigrateLegacyFile("certificates.json", CertificatesFile, migrated);
            TryMigrateLegacyFile("ui-settings.json", ThemeSettingsFile, migrated);
            TryMigrateLegacyFile("dns-secrets.json", DnsSecretsFile, migrated);

            return migrated;
        }

        private static void TryMigrateLegacyFile(string legacyFileName, string targetPath, List<string> migrated)
        {
            var legacyPath = Path.Combine(BaseDirectory, legacyFileName);

            if (!File.Exists(legacyPath))
            {
                return;
            }

            if (!File.Exists(targetPath))
            {
                File.Move(legacyPath, targetPath);
                migrated.Add($"Moved {legacyFileName} to storage.");
                return;
            }

            File.Delete(legacyPath);
            migrated.Add($"Removed legacy {legacyFileName} (storage copy already exists).");
        }
    }
}
