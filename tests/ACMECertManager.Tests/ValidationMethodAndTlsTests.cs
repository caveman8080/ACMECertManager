using System;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ACMECertManager;
using Xunit;

namespace ACMECertManager.Tests;

public sealed class ValidationMethodAndTlsTests
{
    [Theory]
    [InlineData(ChallengeValidationMethod.Http01, "HTTP-01")]
    [InlineData(ChallengeValidationMethod.TlsAlpn01, "TLS-ALPN-01")]
    [InlineData(ChallengeValidationMethod.Dns01, "DNS-01")]
    public void FormatValidationMethod_ReturnsExpectedLabel(ChallengeValidationMethod method, string expected)
    {
        var result = AcmeService.FormatValidationMethod(method);

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("HTTP-01")]
    [InlineData("TLS-ALPN-01")]
    [InlineData("DNS-01")]
    public void CertificateModel_JsonRoundTrip_PreservesValidationMethod(string validationMethod)
    {
        var model = new CertificateModel
        {
            Domain = "example.com",
            ValidationMethod = validationMethod
        };

        var json = JsonSerializer.Serialize(model);
        var loaded = JsonSerializer.Deserialize<CertificateModel>(json);

        Assert.NotNull(loaded);
        Assert.Equal(validationMethod, loaded.ValidationMethod);
    }

    [Fact]
    public void CreateTlsAlpnChallengeCertificate_CreatesExpectedAcmeExtension()
    {
        var method = typeof(AcmeService).GetMethod(
            "CreateTlsAlpnChallengeCertificate",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.NotNull(method);

        using var certificate = (X509Certificate2?)method!.Invoke(
            null,
            new object[] { "example.com", "token.key-authz" });

        Assert.NotNull(certificate);
        Assert.True(certificate.HasPrivateKey);

        var san = certificate.Extensions["2.5.29.17"];
        Assert.NotNull(san);

        var acmeExtension = certificate.Extensions
            .Cast<X509Extension>()
            .FirstOrDefault(ext => string.Equals(ext.Oid?.Value, "1.3.6.1.5.5.7.1.31", StringComparison.Ordinal));

        Assert.NotNull(acmeExtension);
        Assert.True(acmeExtension!.Critical);
        Assert.Equal(34, acmeExtension.RawData.Length);
        Assert.Equal(0x04, acmeExtension.RawData[0]);
        Assert.Equal(0x20, acmeExtension.RawData[1]);

        var expectedDigest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("token.key-authz"));
        var actualDigest = acmeExtension.RawData.Skip(2).ToArray();
        Assert.Equal(expectedDigest, actualDigest);
    }

    [Fact]
    public void TranslateListenerStartException_AccessDenied_ContainsPortAndPolicyGuidance()
    {
        var inner = new SocketException((int)SocketError.AccessDenied);

        var result = TlsAlpnChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 443", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("access was denied", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    [Fact]
    public void TranslateListenerStartException_AddressAlreadyInUse_ContainsPortInUseMessage()
    {
        var inner = new SocketException((int)SocketError.AddressAlreadyInUse);

        var result = TlsAlpnChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 443", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("already in use", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    [Fact]
    public void TranslateListenerStartException_OtherSocketError_IncludesOriginalMessage()
    {
        var inner = new SocketException((int)SocketError.NetworkUnreachable);

        var result = TlsAlpnChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 443", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    [Fact]
    public void HttpChallengeServer_TranslateListenerStartException_AccessDenied_ContainsPortAndAdminGuidance()
    {
        var inner = CreateHttpListenerException(nativeErrorCode: 5, message: "Access is denied");

        var result = HttpChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 80", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("access was denied", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Administrator", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    [Fact]
    public void HttpChallengeServer_TranslateListenerStartException_AlreadyInUse_ContainsPortInUseMessage()
    {
        var inner = CreateHttpListenerException(nativeErrorCode: 32, message: "The process cannot access the file because it is being used by another process.");

        var result = HttpChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 80", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("already in use", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    [Fact]
    public void HttpChallengeServer_TranslateListenerStartException_OtherError_IncludesOriginalMessage()
    {
        var inner = CreateHttpListenerException(nativeErrorCode: 1234, message: "unexpected listener failure");

        var result = HttpChallengeServer.TranslateListenerStartException(inner);

        Assert.IsType<InvalidOperationException>(result);
        Assert.Contains("port 80", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("unexpected listener failure", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Same(inner, result.InnerException);
    }

    private static System.Net.HttpListenerException CreateHttpListenerException(int nativeErrorCode, string message)
    {
        // HttpListenerException(errorCode, message) sets NativeErrorCode/ErrorCode from errorCode.
        return new System.Net.HttpListenerException(nativeErrorCode, message);
    }
}
