using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ACMECertManager;
using Certes;
using Certes.Acme;
using Xunit;

namespace ACMECertManager.Tests;

public sealed class PfxExportTests
{
    [Theory]
    [InlineData(KeyAlgorithm.RS256)]
    [InlineData(KeyAlgorithm.ES256)]
    [InlineData(KeyAlgorithm.ES384)]
    public void BuildPfxBytes_ChainExport_LoadsWithEmptyPasswordAndPrivateKey(KeyAlgorithm algorithm)
    {
        var sample = CreateChain(algorithm);
        var logs = new List<string>();

        var pfxBytes = AcmeService.BuildPfxBytes(
            sample.Chain,
            sample.LeafKey,
            "example.com",
            sample.LeafPem,
            sample.LeafKeyPem,
            logs.Add);

        Assert.NotEmpty(pfxBytes);
        Assert.Contains(logs, line => line.Contains("PFX file built successfully", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, line => line.Contains("Falling back", StringComparison.OrdinalIgnoreCase));

        using var loaded = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            string.Empty,
            X509KeyStorageFlags.EphemeralKeySet);
        using var leaf = X509Certificate2.CreateFromPem(sample.LeafPem);

        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(leaf.Thumbprint, loaded.Thumbprint);

        var collection = X509CertificateLoader.LoadPkcs12Collection(
            pfxBytes,
            string.Empty,
            X509KeyStorageFlags.EphemeralKeySet);
        try
        {
            Assert.Contains(collection, cert => cert.Subject.Contains("Test Intermediate CA", StringComparison.Ordinal));
            Assert.Contains(collection, cert => cert.Thumbprint == leaf.Thumbprint);
        }
        finally
        {
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }

    [Fact]
    public void BuildPfxBytes_WhenChainExportFails_FallsBackToLeafOnlyPfx()
    {
        var sample = CreateChain(KeyAlgorithm.RS256);
        var unrelatedKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var logs = new List<string>();

        var pfxBytes = AcmeService.BuildPfxBytes(
            sample.Chain,
            unrelatedKey,
            "example.com",
            sample.LeafPem,
            sample.LeafKeyPem,
            logs.Add);

        Assert.Contains(logs, line => line.Contains("Falling back to leaf-only PFX export", StringComparison.Ordinal));
        using var loaded = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            string.Empty,
            X509KeyStorageFlags.EphemeralKeySet);
        Assert.True(loaded.HasPrivateKey);
        Assert.Contains("example.com", loaded.Subject, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildPfxBytes_WhenLeafFallbackAlsoFails_ThrowsInvalidOperationException()
    {
        var sample = CreateChain(KeyAlgorithm.ES256);
        var unrelatedKey = KeyFactory.NewKey(KeyAlgorithm.ES256);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AcmeService.BuildPfxBytes(
                sample.Chain,
                unrelatedKey,
                "example.com",
                "not-a-certificate",
                "not-a-key",
                null));

        Assert.Contains("leaf-only", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("passwordless PFX", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static ChainSample CreateChain(KeyAlgorithm algorithm)
    {
        var rootKey = KeyFactory.NewKey(algorithm);
        var intermediateKey = KeyFactory.NewKey(algorithm);
        var leafKey = KeyFactory.NewKey(algorithm);

        using var rootAlgorithm = ImportKey(rootKey, algorithm);
        using var intermediateAlgorithm = ImportKey(intermediateKey, algorithm);
        using var leafAlgorithm = ImportKey(leafKey, algorithm);

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);

        using var rootCert = CreateCertificate(
            "CN=Test Root CA",
            rootAlgorithm,
            algorithm,
            issuer: null,
            serial: [1],
            notBefore,
            notAfter,
            isCa: true);
        using var intermediateCert = CreateCertificate(
            "CN=Test Intermediate CA",
            intermediateAlgorithm,
            algorithm,
            issuer: rootCert,
            serial: [2],
            notBefore,
            notAfter,
            isCa: true);
        using var leafCert = CreateCertificate(
            "CN=example.com",
            leafAlgorithm,
            algorithm,
            issuer: intermediateCert,
            serial: [3],
            notBefore,
            notAfter,
            isCa: false);

        var leafPem = leafCert.ExportCertificatePem();
        var chainPem = leafPem + intermediateCert.ExportCertificatePem() + rootCert.ExportCertificatePem();
        return new ChainSample(new CertificateChain(chainPem), leafKey, leafPem, leafKey.ToPem());
    }

    private static X509Certificate2 CreateCertificate(
        string subject,
        AsymmetricAlgorithm key,
        KeyAlgorithm algorithm,
        X509Certificate2? issuer,
        byte[] serial,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        bool isCa)
    {
        CertificateRequest request = algorithm switch
        {
            KeyAlgorithm.RS256 => new CertificateRequest(subject, (RSA)key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            KeyAlgorithm.ES256 => new CertificateRequest(subject, (ECDsa)key, HashAlgorithmName.SHA256),
            KeyAlgorithm.ES384 => new CertificateRequest(subject, (ECDsa)key, HashAlgorithmName.SHA384),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported test key algorithm.")
        };

        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));
        }
        else
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("example.com");
            request.CertificateExtensions.Add(san.Build());
        }

        if (issuer is null)
        {
            return request.CreateSelfSigned(notBefore, notAfter);
        }

        using var signed = request.Create(issuer, notBefore, notAfter, serial);
        if (!isCa)
        {
            return X509CertificateLoader.LoadCertificate(signed.Export(X509ContentType.Cert));
        }

        return algorithm switch
        {
            KeyAlgorithm.RS256 => signed.CopyWithPrivateKey((RSA)key),
            KeyAlgorithm.ES256 or KeyAlgorithm.ES384 => signed.CopyWithPrivateKey((ECDsa)key),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported test key algorithm.")
        };
    }

    private static AsymmetricAlgorithm ImportKey(IKey key, KeyAlgorithm algorithm)
    {
        var pem = key.ToPem();
        switch (algorithm)
        {
            case KeyAlgorithm.RS256:
                var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                return rsa;
            case KeyAlgorithm.ES256:
            case KeyAlgorithm.ES384:
                var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(pem);
                return ecdsa;
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported test key algorithm.");
        }
    }

    private sealed record ChainSample(CertificateChain Chain, IKey LeafKey, string LeafPem, string LeafKeyPem);
}
