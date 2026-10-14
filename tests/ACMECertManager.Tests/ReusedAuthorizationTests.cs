using ACMECertManager;
using Certes.Acme;
using Certes.Acme.Resource;

namespace ACMECertManager.Tests;

public sealed class ReusedAuthorizationTests
{
    [Theory]
    [InlineData(ChallengeValidationMethod.Http01)]
    [InlineData(ChallengeValidationMethod.TlsAlpn01)]
    [InlineData(ChallengeValidationMethod.Dns01)]
    public async Task ValidAuthorization_SkipsRequestedChallengeWithoutCallingChallengeCode(
        ChallengeValidationMethod method)
    {
        var authorization = new FakeAuthorization(ValidDnsOnly("example.com"));
        var order = new FakeOrder();
        using var plugin = new RecordingDnsPlugin();
        using var httpDirectory = new TempDirectory();

        var logs = await ValidateAsync(
            new[] { authorization },
            order,
            method,
            httpDeployment: NetworkPath(httpDirectory.Path),
            dnsPlugin: plugin.Execution);

        Assert.Equal(0, authorization.ChallengesCalls);
        Assert.Empty(plugin.Presented);
        Assert.Empty(System.IO.Directory.EnumerateFileSystemEntries(httpDirectory.Path));
        Assert.Contains(
            "[ACME] Authorization for example.com is already valid (reused), skipping challenge",
            logs);
        Assert.DoesNotContain(logs, line => line.Contains("Starting HTTP challenge server", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, line => line.Contains("Starting temporary TLS challenge server", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, line => line.Contains("Starting DNS challenge validation", StringComparison.Ordinal));
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.Equal(1, order.ResourceCalls);
    }

    [Theory]
    [InlineData(OrderStatus.Ready)]
    [InlineData(OrderStatus.Valid)]
    public async Task AllValidAuthorizations_StillWaitForOrderReady(OrderStatus orderStatus)
    {
        var apex = new FakeAuthorization(ValidDnsOnly("example.com"));
        var wildcard = new FakeAuthorization(ValidDnsOnly("example.com", wildcard: true));
        var order = new FakeOrder(orderStatus);
        using var plugin = new RecordingDnsPlugin();

        var logs = await ValidateAsync(
            new IAuthorizationContext[] { apex, wildcard },
            order,
            ChallengeValidationMethod.Http01,
            dnsPlugin: plugin.Execution);

        Assert.Equal(0, apex.ChallengesCalls);
        Assert.Equal(0, wildcard.ChallengesCalls);
        Assert.Empty(plugin.Presented);
        Assert.Contains(
            "[ACME] Authorization for example.com is already valid (reused), skipping challenge",
            logs);
        Assert.Contains(
            "[ACME] Authorization for *.example.com is already valid (reused), skipping challenge",
            logs);
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.Equal(1, order.ResourceCalls);
    }

    [Fact]
    public async Task ValidAuthorization_NullIdentifier_UsesFallbackAndWildcardFlag()
    {
        var resource = new Authorization
        {
            Status = AuthorizationStatus.Valid,
            Wildcard = true,
            Challenges = new List<Challenge> { new() { Type = ChallengeTypes.Dns01 } }
        };
        var authorization = new FakeAuthorization(resource);
        var order = new FakeOrder();

        var logs = await ValidateAsync(
            new[] { authorization },
            order,
            ChallengeValidationMethod.Dns01,
            fallbackIdentifier: "example.com",
            dnsPlugin: new RecordingDnsPlugin().Execution);

        Assert.Contains(
            "[ACME] Authorization for *.example.com is already valid (reused), skipping challenge",
            logs);
        Assert.Equal(0, authorization.ChallengesCalls);
    }

    [Theory]
    [InlineData(ChallengeValidationMethod.Http01, "HTTP-01")]
    [InlineData(ChallengeValidationMethod.TlsAlpn01, "TLS-ALPN-01")]
    public async Task PendingAuthorization_MissingHttpOrTlsChallenge_NamesIdentifierMethodAndOfferedTypes(
        ChallengeValidationMethod method,
        string methodLabel)
    {
        var authorization = Pending(
            "example.com",
            wildcard: false,
            new[] { ChallengeTypes.Dns01 },
            new FakeChallenge(ChallengeTypes.Dns01));
        var order = new FakeOrder();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            order,
            method));

        Assert.Equal(
            $"{methodLabel} challenge is not available for 'example.com'. Offered challenge types: dns-01.",
            ex.Message);
        Assert.Equal(1, authorization.ChallengesCalls);
        Assert.Equal(0, order.ResourceCalls);
    }

    [Fact]
    public async Task PendingAuthorization_MissingDnsChallenge_NamesOfferedTypes()
    {
        var httpChallenge = new FakeChallenge(ChallengeTypes.Http01);
        var authorization = Pending(
            "example.com",
            wildcard: false,
            new[] { ChallengeTypes.Http01, ChallengeTypes.TlsAlpn01 },
            httpChallenge);
        var order = new FakeOrder();
        using var plugin = new RecordingDnsPlugin();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            order,
            ChallengeValidationMethod.Dns01,
            dnsPlugin: plugin.Execution));

        Assert.Equal(
            "DNS-01 challenge is not available for 'example.com'. Offered challenge types: http-01, tls-alpn-01.",
            ex.Message);
        Assert.Equal(0, httpChallenge.ValidateCalls);
        Assert.Empty(plugin.Presented);
        Assert.Equal(0, order.ResourceCalls);
    }

    [Theory]
    [InlineData(ChallengeValidationMethod.Http01, "HTTP-01")]
    [InlineData(ChallengeValidationMethod.TlsAlpn01, "TLS-ALPN-01")]
    public async Task PendingWildcardAuthorization_MissingChallenge_UsesWildcardName(
        ChallengeValidationMethod method,
        string methodLabel)
    {
        var authorization = Pending(
            "example.com",
            wildcard: true,
            new[] { ChallengeTypes.Dns01 },
            new FakeChallenge(ChallengeTypes.Dns01));
        var order = new FakeOrder();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            order,
            method));

        Assert.Equal(
            $"{methodLabel} challenge is not available for '*.example.com'. Offered challenge types: dns-01.",
            ex.Message);
        Assert.Equal(0, order.ResourceCalls);
    }

    [Fact]
    public async Task PendingWildcardAuthorization_IdentifierAlreadyStarred_IsNotDoubled()
    {
        var authorization = Pending(
            "*.example.com",
            wildcard: true,
            new[] { ChallengeTypes.Dns01 },
            new FakeChallenge(ChallengeTypes.Dns01));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            new FakeOrder(),
            ChallengeValidationMethod.Http01));

        Assert.Equal(
            "HTTP-01 challenge is not available for '*.example.com'. Offered challenge types: dns-01.",
            ex.Message);
    }

    [Fact]
    public async Task PendingAuthorization_NoOfferedChallenges_SaysNone()
    {
        var authorization = new FakeAuthorization(PendingResource("example.com", wildcard: false))
        {
            ChallengesFactory = () => Array.Empty<IChallengeContext>()
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            new FakeOrder(),
            ChallengeValidationMethod.Http01));

        Assert.Equal(
            "HTTP-01 challenge is not available for 'example.com'. Offered challenge types: none.",
            ex.Message);
        Assert.Equal(2, authorization.ChallengesCalls);
    }

    [Fact]
    public async Task PendingAuthorization_ResourceOmitsChallengeList_UsesContextTypes()
    {
        var authorization = new FakeAuthorization(PendingResourceWithoutChallenges("example.com"))
        {
            ChallengesFactory = () => new IChallengeContext[] { new FakeChallenge(ChallengeTypes.Dns01) }
        };

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            new FakeOrder(),
            ChallengeValidationMethod.TlsAlpn01));

        Assert.Equal(
            "TLS-ALPN-01 challenge is not available for 'example.com'. Offered challenge types: dns-01.",
            ex.Message);
    }

    [Fact]
    public async Task PendingDnsAuthorization_WithoutPlugin_ThrowsBeforeChallengeLookup()
    {
        var authorization = Pending(
            "example.com",
            wildcard: false,
            new[] { ChallengeTypes.Dns01 },
            new FakeChallenge(ChallengeTypes.Dns01));
        authorization.ChallengesFactory = null;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => ValidateAsync(
            new[] { authorization },
            new FakeOrder(),
            ChallengeValidationMethod.Dns01));

        Assert.Equal("DNS-01 selected but no DNS plugin configuration was provided.", ex.Message);
        Assert.Equal(0, authorization.ChallengesCalls);
    }

    [Fact]
    public async Task PendingHttpAuthorization_RunsChallengeAndThenOrderReadyWait()
    {
        var challenge = new FakeChallenge(ChallengeTypes.Http01, token: "http-token", keyAuthz: "http-token.thumb");
        var authorization = new FakeAuthorization(
            PendingResource("example.com", wildcard: false, ChallengeTypes.Http01),
            ValidDnsOnly("example.com"))
        {
            ChallengesFactory = () => new IChallengeContext[] { challenge }
        };
        var order = new FakeOrder();
        using var httpDirectory = new TempDirectory();

        var logs = await ValidateAsync(
            new[] { authorization },
            order,
            ChallengeValidationMethod.Http01,
            httpDeployment: NetworkPath(httpDirectory.Path));

        Assert.Equal(1, challenge.ValidateCalls);
        Assert.Equal(1, authorization.ChallengesCalls);
        Assert.Contains(logs, line => line.Contains("Challenge file written to network/local path", StringComparison.Ordinal));
        Assert.Contains(logs, line => line.Contains("[HTTP-01] Challenge validated successfully", StringComparison.Ordinal));
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.DoesNotContain(logs, line => line.Contains("already valid (reused)", StringComparison.Ordinal));
        Assert.DoesNotContain(logs, line => line.Contains("Starting HTTP challenge server", StringComparison.Ordinal));
        Assert.False(File.Exists(Path.Join(httpDirectory.Path, "http-token")));
        Assert.Equal(1, order.ResourceCalls);
    }

    [Fact]
    public async Task PendingDnsAuthorization_RunsPluginAndValidates()
    {
        var challenge = new FakeChallenge(ChallengeTypes.Dns01, token: "dns-token", keyAuthz: "dns-token.thumb");
        var authorization = new FakeAuthorization(
            PendingResource("example.com", wildcard: false, ChallengeTypes.Dns01),
            ValidDnsOnly("example.com"))
        {
            ChallengesFactory = () => new IChallengeContext[] { challenge }
        };
        var order = new FakeOrder();
        using var plugin = new RecordingDnsPlugin();

        var logs = await ValidateAsync(
            new[] { authorization },
            order,
            ChallengeValidationMethod.Dns01,
            dnsPlugin: plugin.Execution);

        Assert.Equal(1, challenge.ValidateCalls);
        Assert.Single(plugin.Presented);
        Assert.Equal("example.com", plugin.Presented[0].Domain);
        Assert.Equal("_acme-challenge.example.com", plugin.Presented[0].RecordName);
        Assert.Equal(challenge.Token, plugin.Presented[0].Token);
        Assert.Equal(challenge.KeyAuthz, plugin.Presented[0].KeyAuthorization);
        Assert.False(string.IsNullOrWhiteSpace(plugin.Presented[0].TxtValue));
        Assert.Single(plugin.Cleaned);
        Assert.Contains(
            "[DNS-01] Presenting DNS challenge using plugin 'Recording DNS' for example.com",
            logs);
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.Equal(1, order.ResourceCalls);
    }

    [Fact]
    public async Task PendingWildcardDnsAuthorization_PresentsBaseDomainRecord()
    {
        var challenge = new FakeChallenge(ChallengeTypes.Dns01, token: "wild-token", keyAuthz: "wild-token.thumb");
        var authorization = new FakeAuthorization(
            PendingResource("example.com", wildcard: true, ChallengeTypes.Dns01),
            ValidDnsOnly("example.com", wildcard: true))
        {
            ChallengesFactory = () => new IChallengeContext[] { challenge }
        };
        var order = new FakeOrder();
        using var plugin = new RecordingDnsPlugin();

        var logs = await ValidateAsync(
            new[] { authorization },
            order,
            ChallengeValidationMethod.Dns01,
            dnsPlugin: plugin.Execution);

        Assert.Equal(1, challenge.ValidateCalls);
        Assert.Equal("example.com", plugin.Presented[0].Domain);
        Assert.Equal("_acme-challenge.example.com", plugin.Presented[0].RecordName);
        Assert.Contains(
            "[DNS-01] Presenting DNS challenge using plugin 'Recording DNS' for *.example.com",
            logs);
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.Equal(1, order.ResourceCalls);
    }

    [Fact]
    public async Task MixedAuthorizations_SkipsReusedAndRunsPending()
    {
        var reused = new FakeAuthorization(ValidDnsOnly("www.example.com"));
        var challenge = new FakeChallenge(ChallengeTypes.Http01, token: "mixed-token", keyAuthz: "mixed-token.thumb");
        var pending = new FakeAuthorization(
            PendingResource("example.com", wildcard: false, ChallengeTypes.Http01),
            ValidDnsOnly("example.com"))
        {
            ChallengesFactory = () => new IChallengeContext[] { challenge }
        };
        var order = new FakeOrder();
        using var httpDirectory = new TempDirectory();

        var logs = await ValidateAsync(
            new IAuthorizationContext[] { reused, pending },
            order,
            ChallengeValidationMethod.Http01,
            httpDeployment: NetworkPath(httpDirectory.Path));

        Assert.Equal(0, reused.ChallengesCalls);
        Assert.Equal(1, challenge.ValidateCalls);
        Assert.Contains(
            "[ACME] Authorization for www.example.com is already valid (reused), skipping challenge",
            logs);
        Assert.Contains("[ACME] All authorizations validated, waiting for order to be ready...", logs);
        Assert.Equal(1, order.ResourceCalls);
    }

    private static async Task<List<string>> ValidateAsync(
        IReadOnlyList<IAuthorizationContext> authorizations,
        FakeOrder order,
        ChallengeValidationMethod method,
        string fallbackIdentifier = "fallback.example.com",
        HttpChallengeDeploymentOptions? httpDeployment = null,
        DnsPluginExecution? dnsPlugin = null)
    {
        var logs = new List<string>();
        await AcmeService.ValidateOrderAuthorizationsAsync(
            authorizations,
            order,
            fallbackIdentifier,
            method,
            httpDeployment,
            dnsPlugin,
            logs.Add);
        return logs;
    }

    private static FakeAuthorization Pending(
        string name,
        bool wildcard,
        string[] resourceTypes,
        params IChallengeContext[] contexts)
    {
        return new FakeAuthorization(PendingResource(name, wildcard, resourceTypes))
        {
            ChallengesFactory = () => contexts
        };
    }

    private static Authorization ValidDnsOnly(string name, bool wildcard = false)
    {
        return new Authorization
        {
            Identifier = new Identifier { Type = IdentifierType.Dns, Value = name },
            Status = AuthorizationStatus.Valid,
            Wildcard = wildcard,
            Challenges = new List<Challenge>
            {
                new() { Type = ChallengeTypes.Dns01, Status = ChallengeStatus.Valid, Token = "reused-token" }
            }
        };
    }

    private static Authorization PendingResource(string name, bool wildcard, params string[] challengeTypes)
    {
        return new Authorization
        {
            Identifier = new Identifier { Type = IdentifierType.Dns, Value = name },
            Status = AuthorizationStatus.Pending,
            Wildcard = wildcard,
            Challenges = challengeTypes.Select(type => new Challenge
            {
                Type = type,
                Status = ChallengeStatus.Pending,
                Token = "pending-token"
            }).ToList()
        };
    }

    private static Authorization PendingResourceWithoutChallenges(string name)
    {
        return new Authorization
        {
            Identifier = new Identifier { Type = IdentifierType.Dns, Value = name },
            Status = AuthorizationStatus.Pending,
            Challenges = null
        };
    }

    private static HttpChallengeDeploymentOptions NetworkPath(string directory)
    {
        return new HttpChallengeDeploymentOptions
        {
            Method = HttpChallengeDeploymentMethod.NetworkPath,
            Target = directory,
            PublicValidationUrlTemplate = string.Empty
        };
    }

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
        {
            Path = System.IO.Path.Join(System.IO.Path.GetTempPath(), "acme-authz-" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (System.IO.Directory.Exists(Path))
            {
                System.IO.Directory.Delete(Path, recursive: true);
            }
        }
    }

    private sealed class RecordingDnsPlugin : IDnsValidationPlugin, IDisposable
    {
        public List<DnsChallengeRequest> Presented { get; } = new();
        public List<DnsChallengeRequest> Cleaned { get; } = new();

        public DnsPluginExecution Execution { get; }

        public RecordingDnsPlugin()
        {
            Execution = new DnsPluginExecution
            {
                Plugin = new LoadedDnsPlugin
                {
                    AssemblyPath = "recording.dll",
                    Instance = this
                },
                Credentials = new Dictionary<string, string>
                {
                    ["propagationSeconds"] = "0"
                }
            };
        }

        public DnsPluginMetadata Metadata { get; } = new()
        {
            Id = "recording-dns",
            DisplayName = "Recording DNS"
        };

        public IReadOnlyList<DnsCredentialField> GetCredentialFields() => Array.Empty<DnsCredentialField>();

        public Task PresentChallengeAsync(
            DnsChallengeRequest request,
            IReadOnlyDictionary<string, string> credentials,
            CancellationToken cancellationToken)
        {
            Presented.Add(request);
            return Task.CompletedTask;
        }

        public Task CleanupChallengeAsync(
            DnsChallengeRequest request,
            IReadOnlyDictionary<string, string> credentials,
            CancellationToken cancellationToken)
        {
            Cleaned.Add(request);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
        }
    }

    private sealed class FakeOrder : IOrderContext
    {
        public FakeOrder(OrderStatus status = OrderStatus.Ready)
        {
            Status = status;
        }

        public OrderStatus Status { get; }
        public int ResourceCalls { get; private set; }
        public Uri Location { get; } = new("https://acme.test/order/1");
        public int RetryAfter => 0;

        public Task<Order> Resource()
        {
            ResourceCalls++;
            return Task.FromResult(new Order { Status = Status });
        }

        public Task<IEnumerable<IAuthorizationContext>> Authorizations() =>
            throw new InvalidOperationException("Authorizations() should not be called while validating a loaded order.");

        public Task<Order> Finalize(byte[] csr) => throw new NotSupportedException();

        public Task<CertificateChain> Download(string preferredChain) => throw new NotSupportedException();
    }

    private sealed class FakeAuthorization : IAuthorizationContext
    {
        private readonly Queue<Authorization> _resources = new();

        public FakeAuthorization(params Authorization[] resources)
        {
            if (resources.Length == 0)
            {
                throw new ArgumentException("At least one authorization resource is required.", nameof(resources));
            }

            foreach (var resource in resources)
            {
                _resources.Enqueue(resource);
            }
        }

        public Uri Location { get; } = new("https://acme.test/authz/1");
        public int RetryAfter => 0;
        public int ChallengesCalls { get; private set; }
        public Func<IEnumerable<IChallengeContext>>? ChallengesFactory { get; set; }

        public Task<Authorization> Resource()
        {
            var resource = _resources.Count > 1 ? _resources.Dequeue() : _resources.Peek();
            return Task.FromResult(resource);
        }

        public Task<IEnumerable<IChallengeContext>> Challenges()
        {
            ChallengesCalls++;
            if (ChallengesFactory is null)
            {
                throw new InvalidOperationException("Challenge lookup ran for an authorization that should have been skipped.");
            }

            return Task.FromResult(ChallengesFactory());
        }

        public Task<Authorization> Deactivate() => throw new NotSupportedException();
    }

    private sealed class FakeChallenge : IChallengeContext
    {
        public FakeChallenge(string type, string token = "token", string keyAuthz = "token.key")
        {
            Type = type;
            Token = token;
            KeyAuthz = keyAuthz;
        }

        public string Type { get; }
        public string Token { get; }
        public string KeyAuthz { get; }
        public int ValidateCalls { get; private set; }
        public Uri Location { get; } = new("https://acme.test/chall/1");
        public int RetryAfter => 0;

        public Task<Challenge> Validate()
        {
            ValidateCalls++;
            return Task.FromResult(new Challenge
            {
                Type = Type,
                Token = Token,
                Status = ChallengeStatus.Valid
            });
        }

        public Task<Challenge> Resource() =>
            Task.FromResult(new Challenge
            {
                Type = Type,
                Token = Token,
                Status = ChallengeStatus.Pending
            });
    }
}
