using ACMECertManager;
using System.Net.Http;
using System.Runtime.Versioning;

namespace HurricaneElectricDnsPlugin;

[SupportedOSPlatform("windows")]
public sealed class HurricaneElectricDnsValidationPlugin : IDnsValidationPlugin
{
    private const string DdnsUrl = "https://dyn.dns.he.net/nic/update";
    private static readonly HttpClient HttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    public DnsPluginMetadata Metadata => new()
    {
        Id = "hurricane-electric-ddns",
        DisplayName = "Hurricane Electric - DDNS",
        Description = "DNS-01 via Hurricane Electric DDNS endpoint (dyn.dns.he.net) using a DDNS key."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
    [
        new DnsCredentialField
        {
            Name = "ddnsKey",
            Label = "HE DDNS Key",
            IsRequired = true,
            IsSecret = true,
            Placeholder = "Value from HE DDNS configuration"
        },
        new DnsCredentialField
        {
            Name = "propagationSeconds",
            Label = "DNS propagation wait (seconds)",
            IsRequired = false,
            IsSecret = false,
            Placeholder = "Optional, default 30"
        }
    ];

    public async Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var ddnsKey = GetRequired(credentials, "ddnsKey");
        var hostname = NormalizeHost(request.RecordName);

        var form = new Dictionary<string, string>
        {
            ["hostname"] = hostname,
            ["password"] = ddnsKey,
            ["txt"] = request.TxtValue
        };

        var response = await PostFormAsync(form, cancellationToken).ConfigureAwait(false);
        if (!response.Contains("good", StringComparison.OrdinalIgnoreCase) &&
            !response.Contains("nochg", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Hurricane Electric DDNS update failed. Response: {response}");
        }
    }

    public async Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        // HE DDNS endpoint updates a single target record directly.
        // There is no separate delete operation in this flow.
        await Task.CompletedTask;
    }

    private static string GetRequired(IReadOnlyDictionary<string, string> credentials, string key)
    {
        if (!credentials.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Missing required credential '{key}'.");
        }

        return value.Trim();
    }

    private static async Task<string> PostFormAsync(IReadOnlyDictionary<string, string> fields, CancellationToken cancellationToken)
    {
        using var content = new FormUrlEncodedContent(fields);
        using var request = new HttpRequestMessage(HttpMethod.Post, DdnsUrl)
        {
            Content = content
        };

        using var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"HE API request failed with {(int)response.StatusCode}: {response.ReasonPhrase}");
        }

        return payload;
    }

    private static string NormalizeHost(string host)
    {
        return host.Trim().TrimEnd('.').ToLowerInvariant();
    }
}
