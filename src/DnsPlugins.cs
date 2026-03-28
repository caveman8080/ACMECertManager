using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace ACMECertManager
{
    public sealed class DnsPluginMetadata
    {
        public required string Id { get; init; }
        public required string DisplayName { get; init; }
        public string Description { get; init; } = string.Empty;
    }

    public sealed class DnsCredentialField
    {
        public required string Name { get; init; }
        public required string Label { get; init; }
        public bool IsSecret { get; init; }
        public bool IsRequired { get; init; } = true;
        public string Placeholder { get; init; } = string.Empty;
    }

    public sealed class DnsChallengeRequest
    {
        public required string Domain { get; init; }
        public required string RecordName { get; init; }
        public required string Token { get; init; }
        public required string KeyAuthorization { get; init; }
        public required string TxtValue { get; init; }
    }

    public interface IDnsValidationPlugin
    {
        DnsPluginMetadata Metadata { get; }
        IReadOnlyList<DnsCredentialField> GetCredentialFields();
        Task PresentChallengeAsync(DnsChallengeRequest request, IReadOnlyDictionary<string, string> credentials, CancellationToken cancellationToken);
        Task CleanupChallengeAsync(DnsChallengeRequest request, IReadOnlyDictionary<string, string> credentials, CancellationToken cancellationToken);
    }

    public sealed class LoadedDnsPlugin
    {
        public required string AssemblyPath { get; init; }
        public required IDnsValidationPlugin Instance { get; init; }
        public DnsPluginMetadata Metadata => Instance.Metadata;
        public string DisplayName => Instance.Metadata.DisplayName;

        public override string ToString() => DisplayName;
    }

    public sealed class DnsPluginDiscoveryResult
    {
        public List<LoadedDnsPlugin> Plugins { get; } = new();
        public List<string> Warnings { get; } = new();
    }

    public static class DnsPluginLoader
    {
        public static DnsPluginDiscoveryResult DiscoverPlugins(string pluginsDirectory)
        {
            var result = new DnsPluginDiscoveryResult();

            if (!Directory.Exists(pluginsDirectory))
            {
                return result;
            }

            foreach (var dllPath in Directory.GetFiles(pluginsDirectory, "*.dll", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    var assembly = Assembly.LoadFrom(dllPath);
                    var pluginTypes = assembly
                        .GetTypes()
                        .Where(t => typeof(IDnsValidationPlugin).IsAssignableFrom(t) && !t.IsAbstract && t.GetConstructor(Type.EmptyTypes) is not null)
                        .ToList();

                    if (pluginTypes.Count == 0)
                    {
                        continue;
                    }

                    foreach (var pluginType in pluginTypes)
                    {
                        var plugin = (IDnsValidationPlugin)Activator.CreateInstance(pluginType)!;
                        if (string.IsNullOrWhiteSpace(plugin.Metadata.Id) || string.IsNullOrWhiteSpace(plugin.Metadata.DisplayName))
                        {
                            result.Warnings.Add($"Plugin in {Path.GetFileName(dllPath)} skipped due to invalid metadata.");
                            continue;
                        }

                        result.Plugins.Add(new LoadedDnsPlugin
                        {
                            AssemblyPath = dllPath,
                            Instance = plugin
                        });
                    }
                }
                catch (ReflectionTypeLoadException ex)
                {
                    var loaderError = string.Join(" | ", ex.LoaderExceptions.Where(e => e is not null).Select(e => e!.Message));
                    result.Warnings.Add($"Failed to load plugin assembly {Path.GetFileName(dllPath)}: {loaderError}");
                }
                catch (Exception ex)
                {
                    result.Warnings.Add($"Failed to load plugin assembly {Path.GetFileName(dllPath)}: {ex.Message}");
                }
            }

            return result;
        }
    }
}
