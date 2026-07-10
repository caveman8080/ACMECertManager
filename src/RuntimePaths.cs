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
        public static string AccountFile => Path.Join(StorageDirectory, "acme-account.json"); // legacy name, kept for migration
        public static string CertificatesFile => Path.Join(StorageDirectory, "certificates.json");
        public static string ThemeSettingsFile => Path.Join(StorageDirectory, "ui-settings.json");
        public static string DnsSecretsFile => Path.Join(StorageDirectory, "dns-secrets.json");

        /// <summary>
        /// Path to the legacy single ACME account file (pre-environment-specific accounts).
        /// </summary>
        public static string LegacyAccountFile => Path.Join(BaseDirectory, "acme-account.json");

        /// <summary>
        /// Returns the environment-specific ACME account key file path.
        /// Production and staging now use separate .pem files (acme-account-production.pem / acme-account-staging.pem)
        /// to avoid conflicts when switching between Let's Encrypt environments.
        /// </summary>
        public static string GetAcmeAccountFile(string acmeDirectoryUrl)
        {
            bool isStaging = !string.IsNullOrWhiteSpace(acmeDirectoryUrl) &&
                             acmeDirectoryUrl.Contains("staging", StringComparison.OrdinalIgnoreCase);
            string suffix = isStaging ? "-staging" : "-production";
            return Path.Join(StorageDirectory, $"acme-account{suffix}.pem");
        }

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

            // Additional migration: move legacy account to production-specific file if needed
            // (production was the previous default behavior)
            MigrateLegacyAccountToProduction(migrated);

            return migrated;
        }

        private static void MigrateLegacyAccountToProduction(List<string> migrated)
        {
            var legacyPath = LegacyAccountFile;
            if (!File.Exists(legacyPath))
            {
                return;
            }

            var productionAccountPath = GetAcmeAccountFile(LetsEncryptProductionDirectoryUrl); // will resolve to production
            // Note: We reference a const from AcmeService below via a local copy to avoid dependency issues.

            if (File.Exists(productionAccountPath))
            {
                // Production account already exists, just remove legacy
                File.Delete(legacyPath);
                migrated.Add("Removed legacy acme-account.json (production account already present).");
                return;
            }

            try
            {
                File.Move(legacyPath, productionAccountPath);
                migrated.Add("Moved legacy acme-account.json to acme-account-production.pem (environment-specific accounts).");
            }
            catch (IOException ex)
            {
                migrated.Add($"Failed to migrate legacy account file: {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                migrated.Add($"Failed to migrate legacy account file: {ex.Message}");
            }
            catch (System.Security.SecurityException ex)
            {
                migrated.Add($"Failed to migrate legacy account file: {ex.Message}");
            }
            catch (NotSupportedException ex)
            {
                migrated.Add($"Failed to migrate legacy account file: {ex.Message}");
            }
        }

        // Local copy of the production URL to avoid cross-file dependency in this static class
        private const string LetsEncryptProductionDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";

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
