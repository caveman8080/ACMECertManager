# DNS Plugin Development Guide

ACMECertManager is a small portable Windows app for a few personal certificates. This guide is for writing a DNS plugin DLL that the app loads from the `plugins` folder next to `acm.exe`. Plugins are used only for DNS-01 (including wildcard names). Ready-made plugins are published from https://github.com/caveman8080/ACMECertManager-DnsPlugins.

## Compatibility Model
- ACMECertManager uses its own plugin interface contract.
- The design is inspired by win-acme plugin workflows, but plugins must target this app contract directly.

## Host Assembly
Reference the ACMECertManager assembly and implement the interface:
- ACMECertManager.IDnsValidationPlugin

Related contract types:
- DnsPluginMetadata
- DnsCredentialField
- DnsChallengeRequest

## Required Interface
Implement these members:

```csharp
public interface IDnsValidationPlugin
{
    DnsPluginMetadata Metadata { get; }
    IReadOnlyList<DnsCredentialField> GetCredentialFields();
    Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
    Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken);
}
```

## Minimal Example Plugin
```csharp
using ACMECertManager;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

public sealed class ExampleDnsPlugin : IDnsValidationPlugin
{
    public DnsPluginMetadata Metadata => new()
    {
        Id = "example-dns",
        DisplayName = "Example DNS - API",
        Description = "Sample plugin that demonstrates DNS TXT record operations."
    };

    public IReadOnlyList<DnsCredentialField> GetCredentialFields() => new[]
    {
        new DnsCredentialField
        {
            Name = "apiKey",
            Label = "API Key",
            IsSecret = true,
            IsRequired = true,
            Placeholder = "Enter your provider API key"
        },
        new DnsCredentialField
        {
            Name = "zoneId",
            Label = "Zone ID",
            IsSecret = false,
            IsRequired = true,
            Placeholder = "DNS zone identifier"
        }
    };

    public Task PresentChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        var apiKey = credentials["apiKey"];
        var zoneId = credentials["zoneId"];

        // Create TXT record:
        // Name: request.RecordName
        // Value: request.TxtValue
        // Zone: zoneId
        // Provider auth: apiKey
        return Task.CompletedTask;
    }

    public Task CleanupChallengeAsync(
        DnsChallengeRequest request,
        IReadOnlyDictionary<string, string> credentials,
        CancellationToken cancellationToken)
    {
        // Remove TXT record created during PresentChallengeAsync.
        return Task.CompletedTask;
    }
}
```

## Field Schema
Return credential fields from GetCredentialFields().

Common fields:
- apiKey (secret)
- apiSecret (secret)
- zoneId
- username
- password (secret)

Each field supports:
- Name: machine key
- Label: UI caption
- IsSecret: marks sensitive values in UI messaging
- IsRequired: required validation
- Placeholder: helper text shown under input

## DNS Challenge Values
Your plugin receives:
- Domain: authorization identifier
- RecordName: _acme-challenge.<domain>
- Token: ACME token
- KeyAuthorization: challenge key authorization
- TxtValue: the precomputed DNS TXT value for DNS-01

Plugins should create TXT record values using request.TxtValue.

## Error Behavior
Throw descriptive exceptions from PresentChallengeAsync and CleanupChallengeAsync when operations fail.
The host will surface errors in the UI log and message dialogs.

## Packaging
1. Build your plugin for net10.0 or compatible runtime.
2. Copy plugin DLL and its dependency DLLs into plugins/ beside acm.exe.
3. Launch app and verify plugin appears in DNS plugin dropdown.

## Published Plugins
Pre-built DNS-01 plugins are distributed from https://github.com/caveman8080/ACMECertManager-DnsPlugins.
Download a release zip and copy the DLL files into ACMECertManager/plugins/ beside acm.exe.

## GitHub Distribution Workflow
1. Create a GitHub repository for your plugin source.
2. Add build instructions and required provider setup in README.
3. Create Releases with a zip containing:
    - your plugin DLL
    - dependent DLLs
    - provider setup notes
4. Ask users to copy the extracted DLL files into ACMECertManager/plugins/.

## Versioning Guidance
- Keep plugin Metadata.Id stable across versions.
- Increment semantic versions for releases (for example 1.2.0).
- Document breaking credential schema changes clearly.

## Security Notice
Passwords you type for a plugin are stored as plain text in `storage/dns-secrets.json`. Keep that file where other people on the PC cannot read it.
