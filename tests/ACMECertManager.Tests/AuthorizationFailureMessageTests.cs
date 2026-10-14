using ACMECertManager;
using Certes.Acme;
using Certes.Acme.Resource;

namespace ACMECertManager.Tests;

public sealed class AuthorizationFailureMessageTests
{
    [Fact]
    public void InvalidChallenge_IncludesAcmeErrorTypeAndDetail()
    {
        var resource = new Authorization
        {
            Identifier = new Identifier { Type = IdentifierType.Dns, Value = "example.com" },
            Status = AuthorizationStatus.Invalid,
            Challenges = new List<Challenge>
            {
                new Challenge
                {
                    Type = ChallengeTypes.Http01,
                    Status = ChallengeStatus.Invalid,
                    Error = new AcmeError
                    {
                        Type = "urn:ietf:params:acme:error:unauthorized",
                        Detail = "Invalid response from http://example.com/.well-known/acme-challenge/abc: 404",
                    },
                },
            },
        };

        var message = AcmeService.BuildAuthorizationFailureMessage(resource);

        Assert.Contains("'example.com'", message);
        Assert.Contains("http-01", message);
        Assert.Contains("urn:ietf:params:acme:error:unauthorized - Invalid response from", message);
    }

    [Fact]
    public void NoChallengeError_FallsBackToStatusMessage()
    {
        var resource = new Authorization
        {
            Identifier = new Identifier { Type = IdentifierType.Dns, Value = "example.com" },
            Status = AuthorizationStatus.Invalid,
            Challenges = new List<Challenge> { new Challenge { Type = ChallengeTypes.Http01, Status = ChallengeStatus.Invalid } },
        };

        var message = AcmeService.BuildAuthorizationFailureMessage(resource);

        Assert.Contains("failed with status 'Invalid'", message);
    }

    [Fact]
    public void NullChallenges_DoesNotThrow()
    {
        var resource = new Authorization { Status = AuthorizationStatus.Invalid };
        Assert.Contains("failed with status", AcmeService.BuildAuthorizationFailureMessage(resource));
    }
}
