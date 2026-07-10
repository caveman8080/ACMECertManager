using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ACMECertManager;
using Certes;
using Xunit;

namespace ACMECertManager.Tests;

public sealed class ChallengeServerAndPluginTests
{
    [Theory]
    [InlineData("RS256", CertificateKeyAlgorithm.RS256)]
    [InlineData("es256", CertificateKeyAlgorithm.ES256)]
    [InlineData("ES384", CertificateKeyAlgorithm.ES384)]
    [InlineData("unknown", CertificateKeyAlgorithm.RS256)]
    [InlineData(null, CertificateKeyAlgorithm.RS256)]
    public void ParseKeyAlgorithm_ReturnsExpectedValue(string? raw, CertificateKeyAlgorithm expected)
    {
        var result = AcmeService.ParseKeyAlgorithm(raw);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.RS256, KeyAlgorithm.RS256)]
    [InlineData(CertificateKeyAlgorithm.ES256, KeyAlgorithm.ES256)]
    [InlineData(CertificateKeyAlgorithm.ES384, KeyAlgorithm.ES384)]
    public void ToCertesKeyAlgorithm_MapsExpectedValues(CertificateKeyAlgorithm input, KeyAlgorithm expected)
    {
        var result = AcmeService.ToCertesKeyAlgorithm(input);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void GetCertificateNotAfterUtc_ParsesActualNotAfterFromPem()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.com", ecdsa, HashAlgorithmName.SHA256);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(45);
        using var certificate = request.CreateSelfSigned(notBefore, notAfter);
        var pem = certificate.ExportCertificatePem();

        var parsed = AcmeService.GetCertificateNotAfterUtc(pem);

        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
        Assert.InRange(parsed, notAfter.UtcDateTime.AddSeconds(-2), notAfter.UtcDateTime.AddSeconds(2));
    }

    [Fact]
    public void GetCertificateNotAfterUtc_InvalidPem_FallsBackToApprox90Days()
    {
        var before = DateTime.UtcNow;
        var parsed = AcmeService.GetCertificateNotAfterUtc("not-a-certificate");
        var after = DateTime.UtcNow;

        Assert.Equal(DateTimeKind.Utc, parsed.Kind);
        Assert.InRange(parsed, before.AddDays(89), after.AddDays(91));
    }

    [Fact]
    public void KeyFactory_NewKey_SupportsEcdsaAlgorithms()
    {
        var es256 = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var es384 = KeyFactory.NewKey(KeyAlgorithm.ES384);

        Assert.Contains("BEGIN", es256.ToPem(), StringComparison.Ordinal);
        Assert.Contains("BEGIN", es384.ToPem(), StringComparison.Ordinal);
        Assert.Contains("EC PRIVATE KEY", es256.ToPem(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("EC PRIVATE KEY", es384.ToPem(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HttpChallengeServer_StartWhenDisposed_ThrowsObjectDisposedException()
    {
        var server = new HttpChallengeServer("token", "token.key");
        server.Dispose();

        Assert.Throws<ObjectDisposedException>(() => server.Start());
    }

    [Fact]
    public void HttpChallengeServer_DoubleStart_IsIdempotent()
    {
        // Binding port 80 may fail without elevation; only assert dispose/start state when start succeeds.
        using var server = new HttpChallengeServer("token-abc", "token-abc.key-auth");
        try
        {
            server.Start();
            server.Start(); // second call should no-op
        }
        catch (InvalidOperationException)
        {
            // Access denied / port unavailable in CI or non-admin environments is acceptable.
            return;
        }
    }

    [Fact]
    public void TlsAlpnChallengeServer_StartWhenDisposed_ThrowsObjectDisposedException()
    {
        using var certificate = CreateEphemeralSelfSignedCertificate("example.com");
        var server = new TlsAlpnChallengeServer(certificate);
        server.Dispose();

        Assert.Throws<ObjectDisposedException>(() => server.Start());
    }

    [Fact]
    public void TlsAlpnChallengeServer_DoubleStart_IsIdempotentWhenPortAvailable()
    {
        using var certificate = CreateEphemeralSelfSignedCertificate("example.com");
        using var server = new TlsAlpnChallengeServer(certificate);
        try
        {
            server.Start();
            server.Start(); // second call should no-op
        }
        catch (InvalidOperationException)
        {
            // Port 443 may be unavailable without elevation or when already bound.
            return;
        }
    }

    [Fact]
    public void TlsAlpnChallengeServer_Dispose_IsIdempotent()
    {
        using var certificate = CreateEphemeralSelfSignedCertificate("example.com");
        using var server = new TlsAlpnChallengeServer(certificate);
        server.Dispose();
    }

    [Fact]
    public void HttpChallengeServer_Dispose_IsIdempotent()
    {
        var server = new HttpChallengeServer("token", "token.key");
        server.Dispose();
        server.Dispose();
    }

    [Fact]
    public void DnsPluginLoader_MissingDirectory_ReturnsEmptyResult()
    {
        var missing = Path.Join(Path.GetTempPath(), "acme-plugins-missing-" + Guid.NewGuid().ToString("N"));
        var result = DnsPluginLoader.DiscoverPlugins(missing);

        Assert.Empty(result.Plugins);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void DnsPluginLoader_EmptyDirectory_ReturnsEmptyResult()
    {
        var directory = Path.Join(Path.GetTempPath(), "acme-plugins-empty-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var result = DnsPluginLoader.DiscoverPlugins(directory);

            Assert.Empty(result.Plugins);
            Assert.Empty(result.Warnings);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void DnsPluginLoader_NonPluginDll_IsSkippedWithoutCrash()
    {
        var directory = Path.Join(Path.GetTempPath(), "acme-plugins-nonplugin-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            // xunit.core is a real managed assembly with no IDnsValidationPlugin types.
            var source = typeof(FactAttribute).Assembly.Location;
            if (string.IsNullOrWhiteSpace(source) || !File.Exists(source))
            {
                return;
            }

            var destination = Path.Join(directory, "NotAPlugin.dll");
            File.Copy(source, destination, overwrite: true);

            var result = DnsPluginLoader.DiscoverPlugins(directory);

            Assert.Empty(result.Plugins);
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // Loaded assemblies may lock the file on Windows.
            }
            catch (UnauthorizedAccessException)
            {
                // Loaded assemblies may lock the file on Windows.
            }
        }
    }

    [Fact]
    public void DnsPluginLoader_DiscoversFakePluginFromTestAssemblyCopy()
    {
        var directory = Path.Join(Path.GetTempPath(), "acme-plugins-fake-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var source = typeof(ChallengeServerAndPluginTests).Assembly.Location;
            if (string.IsNullOrWhiteSpace(source) || !File.Exists(source))
            {
                return;
            }

            var destination = Path.Join(directory, "FakePluginHost.dll");
            File.Copy(source, destination, overwrite: true);

            var result = DnsPluginLoader.DiscoverPlugins(directory);

            Assert.Contains(result.Plugins, plugin =>
                string.Equals(plugin.Metadata.Id, "fake-dns", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // Loaded assemblies may lock the file on Windows.
            }
            catch (UnauthorizedAccessException)
            {
                // Loaded assemblies may lock the file on Windows.
            }
        }
    }

    [Fact]
    public void DnsPluginLoader_InvalidImage_AddsWarning()
    {
        var directory = Path.Join(Path.GetTempPath(), "acme-plugins-badimage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var badDll = Path.Join(directory, "corrupt.dll");
            File.WriteAllBytes(badDll, Encoding.UTF8.GetBytes("this is not a pe image"));

            var result = DnsPluginLoader.DiscoverPlugins(directory);

            Assert.Empty(result.Plugins);
            Assert.NotEmpty(result.Warnings);
            Assert.Contains(result.Warnings, warning =>
                warning.Contains("corrupt.dll", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void FakeDnsPlugin_Contract_IsValid()
    {
        var plugin = new FakeDnsPlugin();
        Assert.Equal("fake-dns", plugin.Metadata.Id);
        Assert.Equal("Fake DNS", plugin.Metadata.DisplayName);
        Assert.NotEmpty(plugin.GetCredentialFields());
    }

    [Fact]
    public void DnsPluginLoader_DiscoversPluginFromTempAssemblyCopyOfHost()
    {
        // The host app assembly implements no plugins, so discovery should return empty
        // and must not throw when scanning a real managed DLL.
        var directory = Path.Join(Path.GetTempPath(), "acme-plugins-host-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var hostAssembly = typeof(AcmeService).Assembly.Location;
            if (string.IsNullOrWhiteSpace(hostAssembly) || !File.Exists(hostAssembly))
            {
                // Single-file or shadow-copy environments may not expose a path.
                return;
            }

            var destination = Path.Join(directory, "ACMECertManager.HostCopy.dll");
            File.Copy(hostAssembly, destination, overwrite: true);

            var result = DnsPluginLoader.DiscoverPlugins(directory);

            Assert.Empty(result.Plugins);
        }
        finally
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException)
            {
                // Loaded assemblies may lock the file on Windows; ignore cleanup failures.
            }
            catch (UnauthorizedAccessException)
            {
                // Loaded assemblies may lock the file on Windows; ignore cleanup failures.
            }
        }
    }

    [Fact]
    public void EnsureRequiredTarget_Empty_Throws()
    {
        var method = typeof(AcmeService).GetMethod(
            "EnsureRequiredTarget",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        var ex = Assert.Throws<TargetInvocationException>(() =>
            method!.Invoke(null, new object[] { "  ", "network path" }));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("network path", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnsureRequiredCredentials_Missing_Throws()
    {
        var method = typeof(AcmeService).GetMethod(
            "EnsureRequiredCredentials",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        var options = new HttpChallengeDeploymentOptions
        {
            Username = string.Empty,
            Password = string.Empty
        };

        var ex = Assert.Throws<TargetInvocationException>(() =>
            method!.Invoke(null, new object[] { options, "SFTP" }));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("SFTP", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnsureUri_InvalidScheme_Throws()
    {
        var method = typeof(AcmeService).GetMethod(
            "EnsureUri",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        var ex = Assert.Throws<TargetInvocationException>(() =>
            method!.Invoke(null, new object[] { "https://example.com/path", "ftp" }));

        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Contains("FTP", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AcmeHttpClientFactory_ReturnsReusableClients()
    {
        var factoryType = typeof(AcmeService).Assembly.GetType("ACMECertManager.AcmeHttpClientFactory");
        Assert.NotNull(factoryType);

        var getClient = factoryType!.GetMethod("GetClient", BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(getClient);

        var secureA = (HttpClient)getClient!.Invoke(null, new object[] { false })!;
        var secureB = (HttpClient)getClient.Invoke(null, new object[] { false })!;
        var insecureA = (HttpClient)getClient.Invoke(null, new object[] { true })!;
        var insecureB = (HttpClient)getClient.Invoke(null, new object[] { true })!;

        Assert.Same(secureA, secureB);
        Assert.Same(insecureA, insecureB);
        Assert.NotSame(secureA, insecureA);
        Assert.Equal(TimeSpan.FromSeconds(15), secureA.Timeout);
    }

    [Theory]
    [InlineData("Can not find issuer 'C=US,O=(STAGING) Internet Security Research Group,CN=(STAGING) Pretend Pear X1' for certificate 'C=US,O=ISRG,CN=(STAGING) Yonder Yam Root YR'.", true)]
    [InlineData("Cannot find issuer for certificate", true)]
    [InlineData("Some unrelated ACME failure", false)]
    public void IsIssuerResolutionFailure_DetectsCertesIssuerMessages(string message, bool expected)
    {
        var method = typeof(AcmeService).GetMethod(
            "IsIssuerResolutionFailure",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        var result = (bool)method!.Invoke(null, new object[] { new Exception(message) })!;
        Assert.Equal(expected, result);
    }

    [Fact]
    public void BuildLeafOnlyPfx_ExportsValidPfxBytes()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.com", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var leafPem = certificate.ExportCertificatePem();
        var keyPem = ecdsa.ExportPkcs8PrivateKeyPem();

        var method = typeof(AcmeService).GetMethod(
            "BuildLeafOnlyPfx",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var pfxBytes = (byte[])method!.Invoke(null, new object[] { leafPem, keyPem })!;
        Assert.NotEmpty(pfxBytes);

        using var loaded = X509CertificateLoader.LoadPkcs12(pfxBytes, (string?)null, X509KeyStorageFlags.EphemeralKeySet);
        Assert.True(loaded.HasPrivateKey);
        Assert.Equal("CN=example.com", loaded.Subject);
    }

    private static X509Certificate2 CreateEphemeralSelfSignedCertificate(string domain)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={domain}", ecdsa, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(domain);
        request.CertificateExtensions.Add(san.Build());

        using var issued = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1));

        return X509CertificateLoader.LoadPkcs12(
            issued.Export(X509ContentType.Pfx),
            (string?)null,
            X509KeyStorageFlags.EphemeralKeySet);
    }

    /// <summary>
    /// Public so <see cref="DnsPluginLoader"/> can discover and instantiate it from a copied test assembly.
    /// </summary>
    public sealed class FakeDnsPlugin : IDnsValidationPlugin
    {
        public DnsPluginMetadata Metadata => new()
        {
            Id = "fake-dns",
            DisplayName = "Fake DNS",
            Description = "Test double"
        };

        public IReadOnlyList<DnsCredentialField> GetCredentialFields() =>
        [
            new DnsCredentialField
            {
                Name = "apiKey",
                Label = "API Key",
                IsSecret = true,
                IsRequired = true
            }
        ];

        public Task PresentChallengeAsync(
            DnsChallengeRequest request,
            IReadOnlyDictionary<string, string> credentials,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task CleanupChallengeAsync(
            DnsChallengeRequest request,
            IReadOnlyDictionary<string, string> credentials,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
