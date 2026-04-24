using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Xunit;
using ACMECertManager;

namespace ACMECertManager.Tests;

public sealed class StorageAndModelTests
{
    [Fact]
    public void ParseHttpDeploymentMethod_ReturnsExpectedValue()
    {
        var parsed = AcmeService.ParseHttpDeploymentMethod("Sftp");

        Assert.Equal(HttpChallengeDeploymentMethod.Sftp, parsed);
    }

    [Fact]
    public void ParseHttpDeploymentMethod_UnknownFallsBackToSelfHosted()
    {
        var parsed = AcmeService.ParseHttpDeploymentMethod("not-a-method");

        Assert.Equal(HttpChallengeDeploymentMethod.SelfHosted, parsed);
    }

    [Fact]
    public void IsStagingDirectoryUrl_DetectsStagingHost()
    {
        Assert.True(AcmeService.IsStagingDirectoryUrl(AcmeService.LetsEncryptStagingDirectoryUrl));
        Assert.False(AcmeService.IsStagingDirectoryUrl(AcmeService.LetsEncryptProductionDirectoryUrl));
    }

    [Fact]
    public void BuildProbeUrl_ReplacesDomainAndTokenPlaceholders()
    {
        var url = AcmeService.BuildProbeUrl(
            "https://edge.example.net/challenge?d={domain}&token={token}",
            "example.com",
            "abc123");

        Assert.Equal("https://edge.example.net/challenge?d=example.com&token=abc123", url);
    }

    [Fact]
    public void BuildRestPayloadJson_ContainsExpectedFields()
    {
        var payload = AcmeService.BuildRestPayloadJson("present", "example.com", "tok123", "tok123.key");

        using var json = JsonDocument.Parse(payload);
        var root = json.RootElement;
        Assert.Equal("present", root.GetProperty("action").GetString());
        Assert.Equal("example.com", root.GetProperty("domain").GetString());
        Assert.Equal("tok123", root.GetProperty("token").GetString());
        Assert.Equal("tok123.key", root.GetProperty("keyAuthorization").GetString());
        Assert.Equal("/.well-known/acme-challenge/tok123", root.GetProperty("relativePath").GetString());
    }

    [Fact]
    public void CertificateModel_UsesExpectedDefaults()
    {
        var model = new CertificateModel();

        Assert.Equal(string.Empty, model.Domain);
        Assert.Equal(string.Empty, model.Status);
        Assert.Equal(string.Empty, model.PfxPath);
        Assert.Equal(string.Empty, model.OutputDirectory);
        Assert.Equal(string.Empty, model.CertificatePemPath);
        Assert.Equal(string.Empty, model.ChainPemPath);
        Assert.Equal(string.Empty, model.FullChainPemPath);
        Assert.Equal(string.Empty, model.PrivateKeyPemPath);
        Assert.Equal(string.Empty, model.AcmeDirectoryUrl);
        Assert.Equal("HTTP-01", model.ValidationMethod);
    }

    [Fact]
    public void DnsSecretEntry_ValuesSetterCreatesLegacySingleCredential()
    {
        var entry = new DnsSecretEntry();
        var values = new Dictionary<string, string>
        {
            ["apiKey"] = "secret",
            ["zone"] = "example.com"
        };

        entry.Values = values;

        Assert.Single(entry.Credentials);
        Assert.Equal(string.Empty, entry.Credentials[0].Domain);
        Assert.Equal("secret", entry.Credentials[0].Values["apiKey"]);
        Assert.Equal("example.com", entry.Credentials[0].Values["zone"]);
    }

    [Fact]
    public void DnsSecretEntry_ValuesGetterReturnsFirstCredentialValues()
    {
        var entry = new DnsSecretEntry
        {
            Credentials = new List<DnsSecretCredential>
            {
                new() { Domain = "first.example.com", Values = new Dictionary<string, string> { ["token"] = "a" } },
                new() { Domain = "second.example.com", Values = new Dictionary<string, string> { ["token"] = "b" } }
            }
        };

        var values = entry.Values;

        Assert.Single(values);
        Assert.Equal("a", values["token"]);
    }

    [Fact]
    public void NormalizeDomainContext_HandlesWildcardAndBlank()
    {
        Assert.Equal("example.com", DnsSecretStorage.NormalizeDomainContext("*.example.com"));
        Assert.Equal("example.com", DnsSecretStorage.NormalizeDomainContext("example.com"));
        Assert.Equal(string.Empty, DnsSecretStorage.NormalizeDomainContext("  "));
    }

    [Fact]
    public void CertificateStorage_SaveThenLoad_RoundTripsCertificates()
    {
        var storageDirectory = Path.Join(AppContext.BaseDirectory, "storage");
        Directory.CreateDirectory(storageDirectory);

        var certificatesPath = Path.Join(storageDirectory, "certificates.json");
        var backup = File.Exists(certificatesPath) ? File.ReadAllText(certificatesPath) : null;

        try
        {
            var input = new List<CertificateModel>
            {
                new()
                {
                    Domain = "example.com",
                    Expires = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                    Status = "Valid",
                    PfxPath = "certs/example.com/certificate.pfx",
                    OutputDirectory = "certs/example.com",
                    CertificatePemPath = "certs/example.com/cert.pem",
                    ChainPemPath = "certs/example.com/chain.pem",
                    FullChainPemPath = "certs/example.com/fullchain.pem",
                    PrivateKeyPemPath = "certs/example.com/privkey.pem",
                    AcmeDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory",
                    ValidationMethod = "HTTP-01"
                }
            };

            CertificateStorage.Save(input);
            var loaded = CertificateStorage.Load();

            var certificate = Assert.Single(loaded);
            Assert.Equal("example.com", certificate.Domain);
            Assert.Equal("Valid", certificate.Status);
            Assert.Equal("certs/example.com/certificate.pfx", certificate.PfxPath);
            Assert.Equal("certs/example.com", certificate.OutputDirectory);
            Assert.Equal("certs/example.com/cert.pem", certificate.CertificatePemPath);
            Assert.Equal("certs/example.com/chain.pem", certificate.ChainPemPath);
            Assert.Equal("certs/example.com/fullchain.pem", certificate.FullChainPemPath);
            Assert.Equal("certs/example.com/privkey.pem", certificate.PrivateKeyPemPath);
            Assert.Equal("https://acme-staging-v02.api.letsencrypt.org/directory", certificate.AcmeDirectoryUrl);
            Assert.Equal("HTTP-01", certificate.ValidationMethod);
            Assert.Equal(new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc), certificate.Expires);
        }
        finally
        {
            if (backup is null)
            {
                if (File.Exists(certificatesPath))
                {
                    File.Delete(certificatesPath);
                }
            }
            else
            {
                File.WriteAllText(certificatesPath, backup);
            }
        }
    }
}

