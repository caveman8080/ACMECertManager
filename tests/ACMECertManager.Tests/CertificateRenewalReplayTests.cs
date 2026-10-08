using System.Text.Json;

namespace ACMECertManager.Tests;

public sealed class CertificateRenewalReplayTests
{
    [Fact]
    public void TryCreate_Http01Record_ReplaysStoredIssueSettings()
    {
        var model = new CertificateModel
        {
            Domain = "example.com",
            Email = "certs@example.com",
            AcmeDirectoryUrl = AcmeService.LetsEncryptStagingDirectoryUrl,
            ValidationMethod = "HTTP-01",
            KeyAlgorithm = "ES256",
            CreatePfxFile = true,
            HttpDeploymentMethod = "SelfHosted",
            HttpTarget = "https://files.example.com/acme",
            HttpUsername = "deploy-user",
            HttpPassword = "not-a-secret",
            HttpPublicValidationUrlTemplate = "http://{domain}/.well-known/acme-challenge/{token}",
            HttpRestMethod = "POST",
            HttpAdditionalHeaderName = "X-Example",
            HttpAdditionalHeaderValue = "example-value",
            HttpBearerToken = "not-a-secret",
            HttpSkipTlsCertificateValidation = true
        };

        var created = CertificateRenewalReplay.TryCreate(model, out var request, out var missing);

        Assert.True(created);
        Assert.Empty(missing);
        Assert.NotNull(request);
        Assert.Equal(new[] { "example.com" }, request.Domains);
        Assert.Equal("certs@example.com", request.Email);
        Assert.Equal(AcmeService.LetsEncryptStagingDirectoryUrl, request.AcmeDirectoryUrl);
        Assert.Equal(ChallengeValidationMethod.Http01, request.ValidationMethod);
        Assert.True(request.CreatePfxFile);
        Assert.Equal(CertificateKeyAlgorithm.ES256, request.KeyAlgorithm);
        Assert.Equal(string.Empty, request.DnsPluginId);

        var http = request.HttpDeployment;
        Assert.NotNull(http);
        Assert.Equal(HttpChallengeDeploymentMethod.SelfHosted, http.Method);
        Assert.Equal("https://files.example.com/acme", http.Target);
        Assert.Equal("deploy-user", http.Username);
        Assert.Equal("not-a-secret", http.Password);
        Assert.Equal("http://{domain}/.well-known/acme-challenge/{token}", http.PublicValidationUrlTemplate);
        Assert.Equal("POST", http.RestMethod);
        Assert.Equal("X-Example", http.AdditionalHeaderName);
        Assert.Equal("example-value", http.AdditionalHeaderValue);
        Assert.Equal("not-a-secret", http.BearerToken);
        Assert.True(http.SkipTlsCertificateValidation);
    }

    [Fact]
    public void TryCreate_Dns01Record_ReplaysPluginIdWithoutHttpOptions()
    {
        var model = new CertificateModel
        {
            Domain = "example.com",
            Email = "certs@example.com",
            AcmeDirectoryUrl = "https://acme.example.test/directory",
            ValidationMethod = "DNS-01",
            KeyAlgorithm = "RS256",
            CreatePfxFile = false,
            DnsPluginId = "example-plugin"
        };

        var created = CertificateRenewalReplay.TryCreate(model, out var request, out var missing);

        Assert.True(created);
        Assert.Empty(missing);
        Assert.NotNull(request);
        Assert.Equal(new[] { "example.com" }, request.Domains);
        Assert.Equal(ChallengeValidationMethod.Dns01, request.ValidationMethod);
        Assert.Equal("example-plugin", request.DnsPluginId);
        Assert.Null(request.HttpDeployment);
        Assert.False(request.CreatePfxFile);
        Assert.Equal(CertificateKeyAlgorithm.RS256, request.KeyAlgorithm);
    }

    [Fact]
    public void TryCreate_DomainList_TrimsWhitespaceAndTrailingEmptyEntries()
    {
        var model = new CertificateModel
        {
            Domain = "a.example, , b.example,",
            Email = "certs@example.com",
            AcmeDirectoryUrl = "https://acme.example.test/directory",
            ValidationMethod = "DNS-01",
            KeyAlgorithm = "ES256",
            CreatePfxFile = true,
            DnsPluginId = "example-plugin"
        };

        var created = CertificateRenewalReplay.TryCreate(model, out var request, out var missing);

        Assert.True(created);
        Assert.Empty(missing);
        Assert.NotNull(request);
        Assert.Equal(new[] { "a.example", "b.example" }, request.Domains);
    }

    [Fact]
    public void TryCreate_OldDnsRecord_ReportsMissingReplaySettings()
    {
        const string json = """
            {
              "Domain": "example.com",
              "Expires": "2030-01-01T00:00:00Z",
              "Status": "Valid",
              "AcmeDirectoryUrl": "https://acme-staging-v02.api.letsencrypt.org/directory",
              "ValidationMethod": "DNS-01"
            }
            """;

        var model = JsonSerializer.Deserialize<CertificateModel>(json);
        Assert.NotNull(model);
        Assert.Equal("example.com", model.Domain);
        Assert.Equal("Valid", model.Status);
        Assert.Equal("DNS-01", model.ValidationMethod);
        Assert.Equal(string.Empty, model.Email);
        Assert.Equal(string.Empty, model.KeyAlgorithm);
        Assert.Null(model.CreatePfxFile);
        Assert.Equal(string.Empty, model.DnsPluginId);
        Assert.Equal(string.Empty, model.HttpDeploymentMethod);

        var created = CertificateRenewalReplay.TryCreate(model, out var request, out var missing);

        Assert.False(created);
        Assert.Null(request);
        Assert.Contains("email", missing);
        Assert.Contains("key algorithm", missing);
        Assert.Contains("PFX choice", missing);
        Assert.Contains("DNS plugin", missing);
        Assert.DoesNotContain("domains", missing);
        Assert.DoesNotContain("ACME directory URL", missing);
        Assert.DoesNotContain("validation method", missing);
        Assert.DoesNotContain("HTTP deployment", missing);
    }
}
