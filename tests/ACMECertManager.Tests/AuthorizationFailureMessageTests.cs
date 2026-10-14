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

    [Fact]
    public void SecondaryValidationTimeout_AppendsFirewallHint()
    {
        var resource = AuthorizationWithDetail(
            "During secondary validation: Timeout during connect (likely firewall problem)");

        var message = AcmeService.BuildAuthorizationFailureMessage(resource);

        Assert.Contains(HttpDeploymentSupport.SecondaryValidationHint, message);
        Assert.Contains("firewall", message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SecondaryValidationInSubproblem_AppendsFirewallHint()
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
                        Type = "urn:ietf:params:acme:error:connection",
                        Detail = "Primary validation failed",
                        Subproblems = new List<AcmeError>
                        {
                            new AcmeError
                            {
                                Type = "urn:ietf:params:acme:error:connection",
                                Detail = "Secondary validation timed out"
                            }
                        }
                    }
                }
            }
        };

        var message = AcmeService.BuildAuthorizationFailureMessage(resource);

        Assert.Contains("subproblems:", message);
        Assert.Contains(HttpDeploymentSupport.SecondaryValidationHint, message);
    }

    [Fact]
    public void SecondaryValidationWithoutConnectionError_DoesNotAppendHint()
    {
        var message = AcmeService.BuildAuthorizationFailureMessage(
            AuthorizationWithDetail("Secondary validation returned 404"));

        Assert.DoesNotContain(HttpDeploymentSupport.SecondaryValidationHint, message);
    }

    [Theory]
    [InlineData("Connection timed out talking to the server")]
    [InlineData("secondary validation succeeded")]
    public void MentionsBlockedSecondaryValidation_RequiresBothPhrases(string detail)
    {
        Assert.False(AcmeService.MentionsBlockedSecondaryValidation(detail));
    }

    [Theory]
    [InlineData("Secondary validation: connection error from another region")]
    [InlineData("Secondary validation connection failure")]
    [InlineData("Secondary validation failed to connect")]
    public void MentionsBlockedSecondaryValidation_AcceptsConnectionErrors(string detail)
    {
        Assert.True(AcmeService.MentionsBlockedSecondaryValidation(detail));
    }

    private static Authorization AuthorizationWithDetail(string detail)
    {
        return new Authorization
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
                        Type = "urn:ietf:params:acme:error:connection",
                        Detail = detail
                    }
                }
            }
        };
    }
}
