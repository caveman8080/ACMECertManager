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
                if (value != null && value.Count > 0)
                {
                    Credentials = new List<DnsSecretCredential>
                    {
                        new DnsSecretCredential { Domain = string.Empty, Values = value }
                    };
                }
                else
                {
                    Credentials = new List<DnsSecretCredential>();
                }
            }
        }
    }

    public static class DnsSecretStorage
    {
        public static List<DnsSecretEntry> LoadAll()
        {
            var path = RuntimePaths.DnsSecretsFile;
            if (!File.Exists(path))
            {
                return new List<DnsSecretEntry>();
            }

            var json = File.ReadAllText(path);
            var entries = JsonSerializer.Deserialize<List<DnsSecretEntry>>(json) ?? new List<DnsSecretEntry>();
            
            // Ensure all entries have initialized Credentials lists
            foreach (var entry in entries)
            {
                if (entry.Credentials == null)
                {
                    entry.Credentials = new List<DnsSecretCredential>();
                }
            }
            
            return entries;
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
            var all = LoadAll();
            var existing = all.FirstOrDefault(e => e.PluginId == pluginId);

            if (existing is null)
            {
                existing = new DnsSecretEntry { PluginId = pluginId };
                all.Add(existing);
            }

            // Use legacy single-entry approach for backward compatibility
            existing.Values = values.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

            SaveAll(all);
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

            // Check if credential for this domain already exists
            var existingCred = existing.Credentials.FirstOrDefault(c => c.Domain == credential.Domain);
            if (existingCred != null)
            {
                existing.Credentials.Remove(existingCred);
            }

            existing.Credentials.Add(credential);
            SaveAll(all);
        }

        public static void DeleteCredential(string pluginId, string domain)
        {
            var all = LoadAll();
            var existing = all.FirstOrDefault(e => e.PluginId == pluginId);
            
            if (existing != null)
            {
                var cred = existing.Credentials.FirstOrDefault(c => c.Domain == domain);
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

        public static void SaveAll(List<DnsSecretEntry> entries)
        {
            var path = RuntimePaths.DnsSecretsFile;
            var json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }
    }
}
