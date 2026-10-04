using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace ACMECertManager
{
    public sealed class DnsSecretCredential
    {
        public string Domain { get; set; } = string.Empty;
        public Dictionary<string, string> Values { get; set; } = new();
    }

    public sealed class DnsSecretEntry
    {
        public string PluginId { get; set; } = string.Empty;
        public List<DnsSecretCredential> Credentials { get; set; } = new();

        // Legacy support: single-entry storage for backward compatibility
        [System.Text.Json.Serialization.JsonIgnore]
        public Dictionary<string, string> Values
        {
            get
            {
                // Return first credential's values if exists, for backward compatibility
                return Credentials.FirstOrDefault()?.Values ?? new Dictionary<string, string>();
            }
            set
            {
                // When setting via old API, replace entire credentials list with single entry
                Credentials = value != null && value.Count > 0
                    ? new List<DnsSecretCredential>
                    {
                        new DnsSecretCredential { Domain = string.Empty, Values = value }
                    }
                    : new List<DnsSecretCredential>();
            }
        }
    }

    public static class DnsSecretStorage
    {
        public static List<DnsSecretEntry> LoadAll()
        {
            RuntimePaths.EnsureRequiredDirectories();

            var path = RuntimePaths.DnsSecretsFile;
            if (!File.Exists(path))
            {
                return new List<DnsSecretEntry>();
            }

            try
            {
                var json = File.ReadAllText(path);
                var entries = JsonSerializer.Deserialize<List<DnsSecretEntry>>(json) ?? new List<DnsSecretEntry>();

                // Ensure all entries have initialized Credentials lists
                foreach (var entry in entries.Where(entry => entry.Credentials == null))
                {
                    entry.Credentials = new List<DnsSecretCredential>();
                }

                return entries;
            }
            catch (JsonException)
            {
                return new List<DnsSecretEntry>();
            }
            catch (IOException)
            {
                return new List<DnsSecretEntry>();
            }
            catch (UnauthorizedAccessException)
            {
                return new List<DnsSecretEntry>();
            }
        }

        public static Dictionary<string, string> GetForPlugin(string pluginId)
        {
            return LoadAll().FirstOrDefault(e => e.PluginId == pluginId)?.Values ?? new Dictionary<string, string>();
        }

        public static List<DnsSecretCredential> GetCredentialsForPlugin(string pluginId)
        {
            return LoadAll().FirstOrDefault(e => e.PluginId == pluginId)?.Credentials ?? new List<DnsSecretCredential>();
        }

        public static void SaveForPlugin(string pluginId, IReadOnlyDictionary<string, string> values)
        {
            SaveForPlugin(pluginId, values, string.Empty);
        }

        public static void SaveForPlugin(string pluginId, IReadOnlyDictionary<string, string> values, string domainContext)
        {
            SaveCredential(pluginId, new DnsSecretCredential
            {
                Domain = NormalizeDomainContext(domainContext),
                Values = values.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
            });
        }

        public static void SaveCredential(string pluginId, DnsSecretCredential credential)
        {
            var all = LoadAll();
            var existing = all.FirstOrDefault(e => e.PluginId == pluginId);

            if (existing is null)
            {
                existing = new DnsSecretEntry { PluginId = pluginId, Credentials = new List<DnsSecretCredential>() };
                all.Add(existing);
            }

            var normalizedDomain = NormalizeDomainContext(credential.Domain);

            // Check if credential for this domain already exists
            var existingCred = existing.Credentials.FirstOrDefault(c =>
                string.Equals(c.Domain, normalizedDomain, System.StringComparison.OrdinalIgnoreCase));
            if (existingCred != null)
            {
                existing.Credentials.Remove(existingCred);
            }

            credential.Domain = normalizedDomain;
            existing.Credentials.Add(credential);
            SaveAll(all);
        }

        public static void DeleteCredential(string pluginId, string domain)
        {
            var all = LoadAll();
            var existing = all.FirstOrDefault(e => e.PluginId == pluginId);

            if (existing != null)
            {
                var normalizedDomain = NormalizeDomainContext(domain);
                var cred = existing.Credentials.FirstOrDefault(c =>
                    string.Equals(c.Domain, normalizedDomain, System.StringComparison.OrdinalIgnoreCase));
                if (cred != null)
                {
                    existing.Credentials.Remove(cred);
                }

                // Remove plugin entry if no credentials left
                if (existing.Credentials.Count == 0)
                {
                    all.Remove(existing);
                }

                SaveAll(all);
            }
        }

        internal static string NormalizeDomainContext(string? domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return string.Empty;
            }

            var normalized = domain.Trim();
            if (normalized.StartsWith("*.", System.StringComparison.Ordinal))
            {
                normalized = normalized[2..];
            }

            return normalized;
        }

        public static void SaveAll(List<DnsSecretEntry> entries)
        {
            RuntimePaths.EnsureRequiredDirectories();

            var path = RuntimePaths.DnsSecretsFile;
            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
    }
}
