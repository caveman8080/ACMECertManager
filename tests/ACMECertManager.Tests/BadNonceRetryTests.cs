using Certes;
using Certes.Acme;

namespace ACMECertManager.Tests;

public sealed class BadNonceRetryTests
{
    [Fact]
    public async Task RetryBadNonceAsync_RetriesUntilSuccessWithinTheLimit()
    {
        var calls = 0;
        var logs = new List<string>();

        var result = await AcmeService.RetryBadNonceAsync(
            () =>
            {
                calls++;
                if (calls < 3)
                {
                    throw BadNonce();
                }

                return Task.FromResult("ok");
            },
            logs.Add,
            "create ACME order",
            retryDelay: TimeSpan.Zero);

        Assert.Equal("ok", result);
        Assert.Equal(3, calls);
        Assert.Equal(2, logs.Count);
        Assert.All(logs, line => Assert.Contains("badNonce during create ACME order", line));
    }

    [Fact]
    public async Task RetryBadNonceAsync_OtherAcmeErrorsAreNotRetried()
    {
        var calls = 0;

        var error = await Assert.ThrowsAsync<AcmeRequestException>(() =>
            AcmeService.RetryBadNonceAsync<bool>(
                async () =>
                {
                    calls++;
                    throw new AcmeRequestException(
                        "Invalid response",
                        new AcmeError
                        {
                            Type = "urn:ietf:params:acme:error:unauthorized",
                            Detail = "Invalid response"
                        });
                },
                _ => { },
                "submit HTTP-01 challenge",
                retryDelay: TimeSpan.Zero));

        Assert.Equal(1, calls);
        Assert.Contains("unauthorized", error.Error.Type, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RetryBadNonceAsync_GivesUpAfterTheBoundedLimit()
    {
        var calls = 0;

        await Assert.ThrowsAsync<AcmeRequestException>(() =>
            AcmeService.RetryBadNonceAsync(
                async () =>
                {
                    calls++;
                    throw BadNonce();
                },
                _ => { },
                "verify ACME account",
                retryDelay: TimeSpan.Zero));

        Assert.Equal(AcmeService.BadNonceRetryLimit, calls);
    }

    [Fact]
    public async Task RetryBadNonceAsync_NonAcmeExceptionsPropagateImmediately()
    {
        var calls = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AcmeService.RetryBadNonceAsync(
                async () =>
                {
                    calls++;
                    throw new InvalidOperationException("not a nonce problem");
                },
                _ => { },
                "download certificate",
                retryDelay: TimeSpan.Zero));

        Assert.Equal(1, calls);
    }

    private static AcmeRequestException BadNonce()
    {
        return new AcmeRequestException(
            "JWS has an invalid anti-replay nonce",
            new AcmeError
            {
                Type = "urn:ietf:params:acme:error:badNonce",
                Detail = "JWS has an invalid anti-replay nonce"
            });
    }
}
