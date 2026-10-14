using System.Net;
using System.Text;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace ACMECertManager.Tests;

public sealed class HttpDeploymentSupportTests
{
    [Theory]
    [InlineData(HttpChallengeDeploymentMethod.NetworkPath, @"\\server\share\.well-known\acme-challenge or C:\path")]
    [InlineData(HttpChallengeDeploymentMethod.Ftp, "ftp://server/path/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.Sftp, "sftp://server/path/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.WebDav, "https://server:port/Share/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.Rest, "https://host/endpoint")]
    public void TargetPlaceholder_MatchesMethod(HttpChallengeDeploymentMethod method, string expected)
    {
        Assert.Equal(expected, HttpDeploymentSupport.TargetPlaceholder(method));
    }

    [Theory]
    [InlineData(HttpChallengeDeploymentMethod.Ftp, "21")]
    [InlineData(HttpChallengeDeploymentMethod.Sftp, "22")]
    [InlineData(HttpChallengeDeploymentMethod.WebDav, "80/443")]
    [InlineData(HttpChallengeDeploymentMethod.Rest, "80/443")]
    public void PortPlaceholder_MatchesMethodDefault(HttpChallengeDeploymentMethod method, string expected)
    {
        Assert.Equal(expected, HttpDeploymentSupport.PortPlaceholder(method));
    }

    [Theory]
    [InlineData(HttpChallengeDeploymentMethod.NetworkPath, @"\\server\share", @"\\server\share\.well-known\acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.NetworkPath, @"C:\wwwroot", @"C:\wwwroot\.well-known\acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.Ftp, "ftp://server/path/", "ftp://server/path/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.Sftp, "sftp://server/files", "sftp://server/files/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.WebDav, "https://server/Share", "https://server/Share/.well-known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.WebDav, "https://server/Share/.Well-Known/acme-challenge/", "https://server/Share/.Well-Known/acme-challenge")]
    [InlineData(HttpChallengeDeploymentMethod.Rest, "https://host/endpoint", "https://host/endpoint")]
    [InlineData(HttpChallengeDeploymentMethod.SelfHosted, "  ignored  ", "ignored")]
    public void NormalizeChallengeTarget_AppendsSuffixUnlessAlreadyPresent(HttpChallengeDeploymentMethod method, string input, string expected)
    {
        Assert.Equal(expected, HttpDeploymentSupport.NormalizeChallengeTarget(method, input));
    }

    [Fact]
    public void ResolvePort_ExplicitPortOverridesUrlAndDefaults()
    {
        var sftp = new Uri("sftp://server/path");
        var ftp = new Uri("ftp://server/path");
        var https = new Uri("https://server/Share");
        var http = new Uri("http://server/Share");

        Assert.Equal(22, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.Sftp, sftp, null));
        Assert.Equal(2222, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.Sftp, sftp, 2222));
        Assert.Equal(21, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.Ftp, ftp, null));
        Assert.Equal(2121, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.Ftp, ftp, 2121));
        Assert.Equal(443, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.WebDav, https, null));
        Assert.Equal(80, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.WebDav, http, null));
        Assert.Equal(8443, HttpDeploymentSupport.ResolvePort(HttpChallengeDeploymentMethod.Rest, https, 8443));
    }

    [Fact]
    public void WithExplicitPort_RewritesHostPortWithoutDroppingThePath()
    {
        Assert.Equal(
            "sftp://server:2222/path/.well-known/acme-challenge",
            HttpDeploymentSupport.WithExplicitPort("sftp://server/path/.well-known/acme-challenge", 2222));
        Assert.Equal(
            "ftp://user:not-a-secret@server:2121/files",
            HttpDeploymentSupport.WithExplicitPort("ftp://user:not-a-secret@server/files", 2121));
        Assert.Equal(
            "https://server/Share",
            HttpDeploymentSupport.WithExplicitPort("https://server/Share", null));
    }

    [Fact]
    public void FormatHostPort_UsesResolvedEndpoint()
    {
        Assert.Equal("nas.example:22", HttpDeploymentSupport.FormatHostPort("nas.example", 22));
        Assert.Equal("nas.example:22", HttpDeploymentSupport.FormatHostPort("deploy-user:not-a-secret@nas.example", 22));
    }

    [Fact]
    public void RedactUrlForLog_StripsUserInfoQueryAndFragment()
    {
        Assert.Equal(
            "https://nas.example:8443/Share/.well-known/acme-challenge/token?…",
            HttpDeploymentSupport.RedactUrlForLog(
                "https://deploy-user:not-a-secret@nas.example:8443/Share/.well-known/acme-challenge/token?access=not-a-secret#frag"));
        Assert.Equal(
            "ftp://server/files/.well-known/acme-challenge",
            HttpDeploymentSupport.RedactUrlForLog("ftp://deploy-user:not-a-secret@server/files/.well-known/acme-challenge"));
        Assert.Equal(
            "sftp://server:2222/files?…",
            HttpDeploymentSupport.RedactUrlForLog("sftp://deploy-user:not-a-secret@server:2222/files?x=not-a-secret"));
        Assert.Equal(
            "https://host/endpoint?…",
            HttpDeploymentSupport.RedactUrlForLog("https://host/endpoint#not-a-secret"));
        Assert.Equal(
            "https://host/path",
            HttpDeploymentSupport.RedactUrlForLog("https://deploy-user@host/path"));
        Assert.Equal(
            "https://[2001:db8::1]/Share?…",
            HttpDeploymentSupport.RedactUrlForLog("https://deploy-user:not-a-secret@[2001:db8::1]/Share?x=not-a-secret"));
    }

    [Fact]
    public void RedactUrlForLog_LeavesPathsAndCleanUrlsAlone()
    {
        Assert.Equal(string.Empty, HttpDeploymentSupport.RedactUrlForLog(null));
        Assert.Equal(@"C:\www\.well-known\acme-challenge", HttpDeploymentSupport.RedactUrlForLog(@"C:\www\.well-known\acme-challenge"));
        Assert.Equal(@"\\server\share\token", HttpDeploymentSupport.RedactUrlForLog(@"\\server\share\token"));
        Assert.Equal("/files/token", HttpDeploymentSupport.RedactUrlForLog("/files/token"));
        Assert.Equal("https://host/endpoint", HttpDeploymentSupport.RedactUrlForLog("https://host/endpoint"));
    }

    [Fact]
    public void RedactUrlForLog_RedactsUrlsEmbeddedInLogAndErrorText()
    {
        const string secret = "not-a-secret";
        var message = HttpDeploymentSupport.RedactUrlForLog(
            "Presented challenge via REST endpoint: https://deploy-user:" + secret + "@host/hook?token=" + secret);

        Assert.Equal("Presented challenge via REST endpoint: https://host/hook?…", message);
        Assert.DoesNotContain(secret, message);

        var conflict = HttpDeploymentSupport.WebDavConflictMessage(
            "https://deploy-user:" + secret + "@nas.example/Share/missing?x=" + secret);
        Assert.Contains("https://nas.example/Share/missing?…", conflict);
        Assert.DoesNotContain(secret, conflict);

        var status = Assert.Throws<InvalidOperationException>(() =>
            HttpDeploymentSupport.EnsureWebDavMkcolStatus(
                (int)HttpStatusCode.InternalServerError,
                "https://deploy-user:" + secret + "@nas.example/Share"));
        Assert.Contains("https://nas.example/Share", status.Message);
        Assert.DoesNotContain(secret, status.Message);
    }

    [Fact]
    public void ListWebDavCollectionUrls_IncludesEachFolder()
    {
        var urls = HttpDeploymentSupport.ListWebDavCollectionUrls(
            "https://nas.example:5001/Share/.well-known/acme-challenge");

        Assert.Equal(
            new[]
            {
                "https://nas.example:5001/Share",
                "https://nas.example:5001/Share/.well-known",
                "https://nas.example:5001/Share/.well-known/acme-challenge"
            },
            urls);
    }

    [Fact]
    public void EnsureWebDavMkcolStatus_ConflictExplainsParentOrCase()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => HttpDeploymentSupport.EnsureWebDavMkcolStatus((int)HttpStatusCode.Conflict, "https://server/Share/missing"));

        Assert.Contains("parent folder is missing", error.Message);
        Assert.Contains("case-sensitive", error.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.OK)]
    [InlineData(HttpStatusCode.NoContent)]
    [InlineData(HttpStatusCode.MethodNotAllowed)]
    public void EnsureWebDavMkcolStatus_AcceptsCreatedOrAlreadyExists(HttpStatusCode status)
    {
        HttpDeploymentSupport.EnsureWebDavMkcolStatus((int)status, "https://server/Share");
    }

    [Fact]
    public void EnsureWebDavMkcolStatus_OtherStatusNamesTheCode()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => HttpDeploymentSupport.EnsureWebDavMkcolStatus((int)HttpStatusCode.InternalServerError, "https://server/Share"));

        Assert.Contains("500", error.Message);
    }

    [Fact]
    public void UploadSftpChallenge_DoesNotCreateFoldersWhenTheFirstUploadSucceeds()
    {
        var session = new FakeSftpSession();

        HttpDeploymentSupport.UploadSftpChallenge(session, "/Web", "/Web/token", Payload(), null);

        Assert.Equal(1, session.Uploads);
        Assert.Empty(session.Created);
    }

    [Fact]
    public void UploadSftpChallenge_SynologySharedFolder_ToleratesPermissionDeniedAndRetries()
    {
        var session = new FakeSftpSession
        {
            ExistsResult = false,
            FailFirstUpload = true,
            DenyCreate = path => path == "/Web"
        };
        var logs = new List<string>();

        HttpDeploymentSupport.UploadSftpChallenge(
            session,
            "/Web/.well-known/acme-challenge",
            "/Web/.well-known/acme-challenge/token",
            Payload(),
            logs.Add);

        Assert.Equal(2, session.Uploads);
        Assert.Contains("/Web", session.Created);
        Assert.Contains("/Web/.well-known", session.Created);
        Assert.Contains("/Web/.well-known/acme-challenge", session.Created);
        Assert.Contains(logs, line => line.Contains("Creating missing folders", StringComparison.Ordinal));
    }

    [Fact]
    public void UploadSftpChallenge_MissingCheckAndAlreadyExists_StillRetriesTheUpload()
    {
        var session = new FakeSftpSession
        {
            ExistsError = new SftpException(StatusCode.NoSuchFile, "No such file"),
            CreateError = new InvalidOperationException("Folder already exists"),
            FailFirstUpload = true
        };

        HttpDeploymentSupport.UploadSftpChallenge(session, "/files", "/files/token", Payload(), null);

        Assert.Equal(2, session.Uploads);
        Assert.Equal(new[] { "/files" }, session.Created);
    }

    [Fact]
    public void UploadSftpChallenge_SecondFailureIsThrown()
    {
        var session = new FakeSftpSession
        {
            ExistsResult = true,
            FailFirstUpload = true,
            FailLaterUploads = true
        };

        var error = Assert.Throws<IOException>(() =>
            HttpDeploymentSupport.UploadSftpChallenge(session, "/files", "/files/token", Payload(), null));

        Assert.Contains("still missing", error.Message);
    }

    [Fact]
    public void UploadSftpChallenge_CancellationIsNotRetried()
    {
        var session = new FakeSftpSession { CancelUpload = true };

        Assert.Throws<OperationCanceledException>(() =>
            HttpDeploymentSupport.UploadSftpChallenge(session, "/files", "/files/token", Payload(), null));
        Assert.Empty(session.Created);
    }

    [Fact]
    public async Task RunBestEffortCleanupAsync_LogsWarningAndDoesNotThrow()
    {
        var logs = new List<string>();

        await HttpDeploymentSupport.RunBestEffortCleanupAsync(
            () => throw new InvalidOperationException("remote delete denied"),
            logs.Add,
            "[HTTP-01]");

        Assert.Contains(logs, line => line.Contains("Cleanup warning: remote delete denied", StringComparison.Ordinal));
    }

    [Fact]
    public void ShouldProbe_RespectsDisableFlagAndBlankTemplate()
    {
        Assert.False(HttpDeploymentSupport.ShouldProbe(new HttpChallengeDeploymentOptions
        {
            DisablePublicProbe = true,
            PublicValidationUrlTemplate = "http://{domain}/.well-known/acme-challenge/{token}"
        }));
        Assert.False(HttpDeploymentSupport.ShouldProbe(new HttpChallengeDeploymentOptions
        {
            PublicValidationUrlTemplate = "  "
        }));
        Assert.True(HttpDeploymentSupport.ShouldProbe(new HttpChallengeDeploymentOptions
        {
            PublicValidationUrlTemplate = "http://{domain}/.well-known/acme-challenge/{token}"
        }));
    }

    [Fact]
    public void CreateHttpDeploymentOptions_PreservesPasswordAndBearerAndNormalizesTarget()
    {
        var options = AcmeService.CreateHttpDeploymentOptions(
            HttpChallengeDeploymentMethod.Sftp,
            "  sftp://server/www  ",
            "  deploy-user  ",
            "  not-a-secret  ",
            "  http://{domain}/.well-known/acme-challenge/{token}  ",
            " post ",
            " X-Example ",
            " example-value ",
            "  not-a-secret  ",
            skipTlsCertificateValidation: true,
            port: 2222,
            disablePublicProbe: true);

        Assert.Equal("sftp://server/www/.well-known/acme-challenge", options.Target);
        Assert.Equal("deploy-user", options.Username);
        Assert.Equal("  not-a-secret  ", options.Password);
        Assert.Equal("  not-a-secret  ", options.BearerToken);
        Assert.Equal("example-value", options.AdditionalHeaderValue);
        Assert.Equal(2222, options.Port);
        Assert.True(options.SkipTlsCertificateValidation);
        Assert.True(options.DisablePublicProbe);
        Assert.Equal("post", options.RestMethod);
    }

    [Fact]
    public void CreateHttpDeploymentOptions_BlankOrOutOfRangePortIsOmitted()
    {
        var options = AcmeService.CreateHttpDeploymentOptions(
            HttpChallengeDeploymentMethod.Ftp,
            "ftp://server/www",
            "user",
            "not-a-secret",
            null,
            null,
            null,
            null,
            null,
            false,
            0,
            false);

        Assert.Null(options.Port);
        Assert.False(options.DisablePublicProbe);
    }

    [Fact]
    public void DescribeAcmeDirectory_DistinguishesProductionStagingAndCustom()
    {
        Assert.Equal("PRODUCTION (real)", AcmeService.DescribeAcmeDirectory(AcmeService.LetsEncryptProductionDirectoryUrl));
        Assert.Equal("STAGING (safe)", AcmeService.DescribeAcmeDirectory(AcmeService.LetsEncryptStagingDirectoryUrl));
        Assert.Equal("CUSTOM (ca.example)", AcmeService.DescribeAcmeDirectory("https://ca.example/directory"));
        Assert.Equal(
            "CUSTOM (acme-v02.api.letsencrypt.org)",
            AcmeService.DescribeAcmeDirectory("http://acme-v02.api.letsencrypt.org/directory"));
        Assert.False(AcmeService.IsLetsEncryptProductionDirectory("https://ca.example/acme-v02.api.letsencrypt.org"));
    }

    [Fact]
    public void GetClient_SkipTlsUsesASeparateClient()
    {
        var normal = AcmeHttpClientFactory.GetClient(skipTlsValidation: false);
        var insecure = AcmeHttpClientFactory.GetClient(skipTlsValidation: true);

        Assert.NotSame(normal, insecure);
        Assert.Same(insecure, AcmeHttpClientFactory.GetClient(skipTlsValidation: true));
    }

    [Fact]
    public void HttpChallengeContentType_IsOctetStream()
    {
        Assert.Equal("application/octet-stream", HttpDeploymentSupport.HttpChallengeContentType);
    }

    private static byte[] Payload() => Encoding.UTF8.GetBytes("key-auth\n");

    private sealed class FakeSftpSession : ISftpFileSession
    {
        public int Uploads { get; private set; }
        public List<string> Created { get; } = new();
        public bool ExistsResult { get; init; } = true;
        public Exception? ExistsError { get; init; }
        public bool FailFirstUpload { get; init; }
        public bool FailLaterUploads { get; init; }
        public bool CancelUpload { get; init; }
        public Func<string, bool>? DenyCreate { get; init; }
        public Exception? CreateError { get; init; }

        public bool Exists(string path)
        {
            if (ExistsError is not null)
            {
                throw ExistsError;
            }

            return ExistsResult;
        }

        public void CreateDirectory(string path)
        {
            Created.Add(path);
            if (DenyCreate?.Invoke(path) == true)
            {
                throw new SftpPermissionDeniedException("Permission denied");
            }

            if (CreateError is not null)
            {
                throw CreateError;
            }
        }

        public void UploadFile(Stream input, string path, bool canOverride)
        {
            Uploads++;
            if (CancelUpload)
            {
                throw new OperationCanceledException();
            }

            if (FailFirstUpload && Uploads == 1 || FailLaterUploads && Uploads > 1)
            {
                throw new IOException("still missing");
            }
        }
    }
}
