using System;
using System.Collections.Generic;
using System.IO;

namespace ACMECertManager
{
    internal static class RuntimePaths
    {
        public static string BaseDirectory => AppContext.BaseDirectory;
        public static string PluginsDirectory => Path.Join(BaseDirectory, "plugins");
        public static string LogsDirectory => Path.Join(BaseDirectory, "logs");
        public static string CertsDirectory => Path.Join(BaseDirectory, "certs");
        public static string StorageDirectory => Path.Join(BaseDirectory, "storage");

        public static string LogFile => Path.Join(LogsDirectory, "acm.log");
        public static string AccountFile => Path.Join(StorageDirectory, "acme-account.json");
        public static string CertificatesFile => Path.Join(StorageDirectory, "certificates.json");
        public static string ThemeSettingsFile => Path.Join(StorageDirectory, "ui-settings.json");
        public static string DnsSecretsFile => Path.Join(StorageDirectory, "dns-secrets.json");

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
            var legacyPath = Path.Join(BaseDirectory, legacyFileName);

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
