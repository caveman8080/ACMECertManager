namespace ACMECertManager.Tests;

public sealed class HttpUploadCredentialStoreTests
{
    [Fact]
    public void List_SkipsSelfHostedAndEmptyMethods()
    {
        var certificates = new List<CertificateModel>
        {
            new()
            {
                Domain = "self.example",
                HttpDeploymentMethod = "SelfHosted",
                HttpPassword = "not-a-secret"
            },
            new() { Domain = "old.example" },
            new()
            {
                Domain = "files.example",
                OutputDirectory = @"C:\certs\files.example",
                HttpDeploymentMethod = "Sftp",
                HttpTarget = "sftp://server/www",
                HttpPort = 2222,
                HttpUsername = "deploy-user",
                HttpPassword = "  not-a-secret  ",
                HttpBearerToken = "  not-a-secret  ",
                HttpAdditionalHeaderValue = "example-value"
            }
        };

        var listed = HttpUploadCredentialStore.List(certificates);

        Assert.Single(listed);
        Assert.Equal("files.example", listed[0].Domain);
        Assert.Equal("  not-a-secret  ", listed[0].Password);
        Assert.Equal(2222, listed[0].Port);
    }

    [Fact]
    public void TryApply_WritesBackWithoutTrimmingSecrets()
    {
        var match = new CertificateModel
        {
            Domain = "files.example",
            OutputDirectory = @"C:\certs\files.example",
            HttpDeploymentMethod = "Ftp",
            HttpTarget = "ftp://old/path",
            HttpPassword = "old"
        };
        var other = new CertificateModel
        {
            Domain = "files.example",
            OutputDirectory = @"C:\certs\other",
            HttpDeploymentMethod = "Ftp",
            HttpTarget = "ftp://old/path",
            HttpPassword = "leave-me"
        };
        var certificates = new List<CertificateModel> { other, match };

        var applied = HttpUploadCredentialStore.TryApply(certificates, new HttpUploadCredentialRecord
        {
            Domain = "files.example",
            OutputDirectory = @"C:\certs\files.example",
            DeploymentMethod = "Ftp",
            Target = "ftp://server/www/",
            Port = 2121,
            Username = " deploy-user ",
            Password = "  not-a-secret  ",
            BearerToken = "  not-a-secret  ",
            AdditionalHeaderValue = " example-value "
        }, out var error);

        Assert.True(applied);
        Assert.Equal(string.Empty, error);
        Assert.Equal("ftp://server/www/.well-known/acme-challenge", match.HttpTarget);
        Assert.Equal(2121, match.HttpPort);
        Assert.Equal("deploy-user", match.HttpUsername);
        Assert.Equal("  not-a-secret  ", match.HttpPassword);
        Assert.Equal("  not-a-secret  ", match.HttpBearerToken);
        Assert.Equal(" example-value ", match.HttpAdditionalHeaderValue);
        Assert.Equal("leave-me", other.HttpPassword);
        Assert.Equal("ftp://old/path", other.HttpTarget);
    }

    [Fact]
    public void TryApply_MatchesDomainAndMethodWhenOutputFolderIsMissing()
    {
        var match = new CertificateModel
        {
            Domain = "rest.example",
            HttpDeploymentMethod = "Rest",
            HttpTarget = "https://old.example/hook"
        };

        var applied = HttpUploadCredentialStore.TryApply(
            new List<CertificateModel> { match },
            new HttpUploadCredentialRecord
            {
                Domain = "rest.example",
                DeploymentMethod = "Rest",
                Target = "https://host/endpoint"
            },
            out var error);

        Assert.True(applied);
        Assert.Equal(string.Empty, error);
        Assert.Equal("https://host/endpoint", match.HttpTarget);
    }

    [Fact]
    public void TryApply_RejectsAnOutOfRangePort()
    {
        var match = new CertificateModel
        {
            Domain = "files.example",
            OutputDirectory = @"C:\certs\files.example",
            HttpDeploymentMethod = "Sftp"
        };

        var applied = HttpUploadCredentialStore.TryApply(
            new List<CertificateModel> { match },
            new HttpUploadCredentialRecord
            {
                OutputDirectory = @"C:\certs\files.example",
                Port = 0,
                Password = "not-a-secret"
            },
            out var error);

        Assert.False(applied);
        Assert.Contains("1 to 65535", error);
        Assert.Equal(string.Empty, match.HttpPassword);
    }

    [Fact]
    public void Mask_HidesValuesUntilRevealed()
    {
        Assert.Equal(string.Empty, HttpUploadCredentialStore.Mask(null, revealed: false));
        Assert.Equal("••••••", HttpUploadCredentialStore.Mask("not-a-secret", revealed: false));
        Assert.Equal("not-a-secret", HttpUploadCredentialStore.Mask("not-a-secret", revealed: true));
    }
}
