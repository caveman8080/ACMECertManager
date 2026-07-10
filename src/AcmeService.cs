using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentFTP;
using Renci.SshNet;

namespace ACMECertManager
{
    public enum ChallengeValidationMethod
    {
        Http01,
        TlsAlpn01,
        Dns01
    }

    public enum HttpChallengeDeploymentMethod
    {
        SelfHosted,
        NetworkPath,
        Ftp,
        Sftp,
        WebDav,
        Rest
    }

    public sealed class HttpChallengeDeploymentOptions
    {
        public HttpChallengeDeploymentMethod Method { get; init; } = HttpChallengeDeploymentMethod.SelfHosted;
        public string Target { get; init; } = string.Empty;
        public string Username { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string PublicValidationUrlTemplate { get; init; } = "http://{domain}/.well-known/acme-challenge/{token}";
        public string RestMethod { get; init; } = "POST";
        public string AdditionalHeaderName { get; init; } = string.Empty;
        public string AdditionalHeaderValue { get; init; } = string.Empty;
        public string BearerToken { get; init; } = string.Empty;
        public bool SkipTlsCertificateValidation { get; init; }
    }

    public sealed class DnsPluginExecution
    {
        public required LoadedDnsPlugin Plugin { get; init; }
        public required IReadOnlyDictionary<string, string> Credentials { get; init; }
    }

    /// <summary>
    /// Certificate private-key algorithms supported for ACME finalization.
    /// Maps to Certes <see cref="KeyAlgorithm"/> values.
    /// </summary>
    public enum CertificateKeyAlgorithm
    {
        RS256,
        ES256,
        ES384
    }

    /// <summary>
    /// Shared HttpClient factory with pooled handlers for deployment/probe traffic.
    /// Clients are long-lived; callers must not dispose them and should attach auth per-request.
    /// </summary>
    internal static class AcmeHttpClientFactory
    {
        private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);

        private static readonly SocketsHttpHandler SharedHandler = CreateHandler(skipTlsValidation: false);
        private static readonly SocketsHttpHandler InsecureHandler = CreateHandler(skipTlsValidation: true);

        private static readonly HttpClient SharedClient = CreateClient(SharedHandler);
        private static readonly HttpClient InsecureClient = CreateClient(InsecureHandler);

        public static HttpClient GetClient(bool skipTlsValidation) =>
            skipTlsValidation ? InsecureClient : SharedClient;

        private static SocketsHttpHandler CreateHandler(bool skipTlsValidation)
        {
            var handler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
                MaxConnectionsPerServer = 20,
                ConnectTimeout = TimeSpan.FromSeconds(10)
            };

            if (skipTlsValidation)
            {
                handler.SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true
                };
            }

            return handler;
        }

        private static HttpClient CreateClient(HttpMessageHandler handler) =>
            new(handler, disposeHandler: false)
            {
                Timeout = RequestTimeout
            };
    }

    public class AcmeService
    {
        public const string LetsEncryptProductionDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";
        public const string LetsEncryptStagingDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

        private static readonly TimeSpan DefaultPollDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxWaitForAuthorization = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan MaxWaitForOrderReady = TimeSpan.FromMinutes(2);
        // Post-finalize: CA may keep the order in Processing while issuing the cert.
        private static readonly TimeSpan MaxWaitForOrderValid = TimeSpan.FromMinutes(3);
        // Certes Generate default retryCount is 1; use a higher budget for Processing.
        private const int CertificateGenerateRetryCount = 60;
        private static readonly HashSet<string> ReservedWindowsFileNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        public async Task<CertificateModel> IssueCertificateAsync(
            string[] domains,
            string email,
            string acmeUrl,
            ChallengeValidationMethod validationMethod,
            HttpChallengeDeploymentOptions? httpDeployment,
            DnsPluginExecution? dnsPlugin,
            bool createPfxFile,
            CertificateKeyAlgorithm keyAlgorithm = CertificateKeyAlgorithm.RS256,
            Action<string>? log = null)
        {
            RuntimePaths.EnsureRequiredDirectories();

            log?.Invoke($"[ACME] Starting certificate issuance for domains: {string.Join(", ", domains)}");
            log?.Invoke($"[ACME] ACME Server: {(acmeUrl.Contains("staging") ? "STAGING (safe)" : "PRODUCTION (real)")}");
            log?.Invoke($"[ACME] Validation Method: {validationMethod}");
            if (validationMethod == ChallengeValidationMethod.Http01)
            {
                var httpMethod = httpDeployment?.Method ?? HttpChallengeDeploymentMethod.SelfHosted;
                log?.Invoke($"[HTTP-01] Deployment Method: {httpMethod}");
            }
            else if (validationMethod == ChallengeValidationMethod.TlsAlpn01)
            {
                log?.Invoke("[TLS-ALPN-01] Self-hosted listener will bind to port 443");
            }
            log?.Invoke("[ACME] Account email configured");

            string accountFilePath = RuntimePaths.GetAcmeAccountFile(acmeUrl);
            bool isStaging = IsStagingDirectoryUrl(acmeUrl);

            AcmeContext acme;

            // Account bootstrap: use environment-specific account file (production vs staging)
            if (File.Exists(accountFilePath))
            {
                log?.Invoke($"[ACME] Loading existing account key from {Path.GetFileName(accountFilePath)}...");
                var accountKey = KeyFactory.FromPem(File.ReadAllText(accountFilePath));
                acme = new AcmeContext(new Uri(acmeUrl), accountKey);

                // ACMEv2 servers may require explicit ToS agreement on newAccount.
                // With an existing key this call safely returns the existing account if it already exists.
                await acme.NewAccount(email, true);
                log?.Invoke("[ACME] Account key loaded and verified with ACME server");
            }
            else
            {
                // Check for legacy single account file and migrate if this is production (previous default)
                string legacyPath = RuntimePaths.LegacyAccountFile;
                if (File.Exists(legacyPath) && !isStaging)
                {
                    log?.Invoke("[ACME] Migrating legacy account key to production-specific file...");
                    var legacyPem = File.ReadAllText(legacyPath);
                    File.WriteAllText(accountFilePath, legacyPem);
                    try
                    {
                        File.Delete(legacyPath);
                    }
                    catch (IOException)
                    {
                        // Best-effort cleanup: ignore delete errors.
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Best-effort cleanup: ignore delete errors.
                    }
                    log?.Invoke("[ACME] Legacy account migrated successfully.");

                    var accountKey = KeyFactory.FromPem(legacyPem);
                    acme = new AcmeContext(new Uri(acmeUrl), accountKey);
                    await acme.NewAccount(email, true);
                }
                else
                {
                    log?.Invoke($"[ACME] Creating new ACME account for {(isStaging ? "STAGING" : "PRODUCTION")}...");
                    acme = new AcmeContext(new Uri(acmeUrl));
                    await acme.NewAccount(email, true);
                    File.WriteAllText(accountFilePath, acme.AccountKey.ToPem());
                    log?.Invoke($"[ACME] New account created and persisted to {Path.GetFileName(accountFilePath)}");
                }
            }

            log?.Invoke("[ACME] Creating new order with ACME server...");
            IOrderContext order;
            try
            {
                order = await acme.NewOrder(domains);
            }
            catch (AcmeException ex)
            {
                throw CreateAcmeOperationException("create ACME order", ex);
            }

            log?.Invoke("[ACME] Order created successfully");

            IReadOnlyList<IAuthorizationContext> authorizations;
            try
            {
                // Load authorizations once. Each Authorizations() call re-POSTs the order resource.
                authorizations = (await LoadOrderAuthorizationsAsync(order, log)).ToList();
            }
            catch (AcmeException ex)
            {
                throw CreateAcmeOperationException("load ACME order authorizations", ex);
            }

            log?.Invoke($"[ACME] Order contains {authorizations.Count} authorization(s)");

            var authorizationIndex = 0;
            foreach (var authz in authorizations)
            {
                authorizationIndex++;
                log?.Invoke($"[ACME] Processing authorization {authorizationIndex} of {authorizations.Count}");

                if (validationMethod == ChallengeValidationMethod.Http01)
                {
                    var challenge = await authz.Http();
                    var httpIdentifier = (await authz.Resource()).Identifier?.Value ?? domains[0];
                    await HandleHttpAuthorizationAsync(challenge, authz, httpIdentifier, httpDeployment, log);
                    continue;
                }

                if (validationMethod == ChallengeValidationMethod.TlsAlpn01)
                {
                    var challenge = await authz.TlsAlpn();
                    var tlsIdentifier = (await authz.Resource()).Identifier?.Value ?? domains[0];
                    if (challenge is null)
                    {
                        throw new InvalidOperationException(
                            $"TLS-ALPN-01 challenge is not available for '{tlsIdentifier}' from this ACME server.");
                    }

                    await HandleTlsAuthorizationAsync(challenge, authz, tlsIdentifier, log);
                    continue;
                }

                if (dnsPlugin is null)
                {
                    throw new InvalidOperationException("DNS-01 selected but no DNS plugin configuration was provided.");
                }

                log?.Invoke("[DNS-01] Starting DNS challenge validation...");
                var dnsChallenge = await authz.Dns();
                var dnsIdentifier = (await authz.Resource()).Identifier?.Value ?? domains[0];
                var dnsRequest = new DnsChallengeRequest
                {
                    Domain = dnsIdentifier,
                    RecordName = $"_acme-challenge.{dnsIdentifier}",
                    Token = dnsChallenge.Token,
                    KeyAuthorization = dnsChallenge.KeyAuthz,
                    TxtValue = ComputeDnsTxtValue(dnsChallenge.KeyAuthz)
                };

                log?.Invoke($"[DNS-01] DNS record to create: {dnsRequest.RecordName}");
                log?.Invoke($"[DNS-01] Presenting DNS challenge using plugin '{dnsPlugin.Plugin.Metadata.DisplayName}' for {dnsIdentifier}");
                await dnsPlugin.Plugin.Instance.PresentChallengeAsync(dnsRequest, dnsPlugin.Credentials, CancellationToken.None);
                log?.Invoke("[DNS-01] DNS record presented");

                var propagationDelay = GetDnsPropagationDelay(dnsPlugin.Credentials);
                if (propagationDelay > TimeSpan.Zero)
                {
                    log?.Invoke($"[DNS-01] Waiting {propagationDelay.TotalSeconds:0} seconds for DNS propagation...");
                    await Task.Delay(propagationDelay);
                }

                try
                {
                    log?.Invoke("[DNS-01] Sending challenge validation request to ACME server...");
                    await dnsChallenge.Validate();
                    log?.Invoke("[DNS-01] Waiting for ACME server to verify challenge...");
                    await WaitForAuthorizationValidAsync(authz);
                    log?.Invoke("[DNS-01] DNS challenge validated successfully");
                }
                finally
                {
                    try
                    {
                        log?.Invoke("[DNS-01] Cleaning up DNS record...");
                        await dnsPlugin.Plugin.Instance.CleanupChallengeAsync(dnsRequest, dnsPlugin.Credentials, CancellationToken.None);
                        log?.Invoke("[DNS-01] DNS cleanup completed");
                    }
                    catch (HttpRequestException ex)
                    {
                        log?.Invoke($"[DNS-01] Cleanup warning: {ex.Message}");
                    }
                    catch (IOException ex)
                    {
                        log?.Invoke($"[DNS-01] Cleanup warning: {ex.Message}");
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        log?.Invoke($"[DNS-01] Cleanup warning: {ex.Message}");
                    }
                    catch (System.Security.SecurityException ex)
                    {
                        log?.Invoke($"[DNS-01] Cleanup warning: {ex.Message}");
                    }
                }
            }

            log?.Invoke("[ACME] All authorizations validated, waiting for order to be ready...");
            await WaitForOrderReadyAsync(order);
            log?.Invoke("[ACME] Order is ready for finalization");

            // Generate cert
            var certesKeyAlgorithm = ToCertesKeyAlgorithm(keyAlgorithm);
            log?.Invoke($"[CERT] Generating new private key ({keyAlgorithm})...");
            var privateKey = KeyFactory.NewKey(certesKeyAlgorithm);
            CertificateChain cert;
            try
            {
                log?.Invoke("[CERT] Creating certificate signing request and finalizing order...");
                // Certes Generate finalizes then downloads. Default retryCount is only 1 while the
                // order is Processing; Let's Encrypt commonly needs longer before the cert is ready.
                cert = await order.Generate(
                    new CsrInfo
                    {
                        CommonName = domains[0]
                    },
                    privateKey,
                    preferredChain: null,
                    retryCount: CertificateGenerateRetryCount);
                log?.Invoke("[CERT] Certificate generated successfully from ACME server");
            }
            catch (AcmeException ex)
            {
                // Certes may throw while the order is still Processing (cert not ready yet),
                // or after a transient download failure once the order is already Valid.
                var orderResource = await order.Resource();
                if (orderResource.Status is OrderStatus.Processing or OrderStatus.Valid)
                {
                    log?.Invoke(
                        $"[CERT] Generate reported an error while order is {orderResource.Status} ({ex.Message}); " +
                        "waiting for certificate to become available...");
                    try
                    {
                        cert = await WaitForOrderValidAndDownloadAsync(order, log);
                        log?.Invoke("[CERT] Certificate downloaded successfully after post-finalize wait");
                    }
                    catch (Exception downloadEx) when (downloadEx is not OperationCanceledException)
                    {
                        var details = await BuildOrderFailureDetailsAsync(order);
                        log?.Invoke($"[CERT] ❌ Certificate generation failed: {details} Fallback: {downloadEx.Message}");
                        throw new InvalidOperationException($"Fail to finalize order. {details}", ex);
                    }
                }
                else
                {
                    var details = await BuildOrderFailureDetailsAsync(order);
                    log?.Invoke($"[CERT] ❌ Certificate generation failed: {details}");
                    throw new InvalidOperationException($"Fail to finalize order. {details}", ex);
                }
            }

            var leafCertificatePem = cert.Certificate.ToPem();
            var privateKeyPem = privateKey.ToPem();
            var fullChainPem = TryGetFullChainPem(cert, leafCertificatePem, log);
            var certificateOutputDirectory = GetCertificateOutputDirectory(domains[0]);
            System.IO.Directory.CreateDirectory(certificateOutputDirectory);

            log?.Invoke($"[CERT] Saving certificate files to: {certificateOutputDirectory}");
            var pemPaths = SavePemArtifacts(certificateOutputDirectory, leafCertificatePem, fullChainPem, privateKeyPem, log);

            var pfxPath = string.Empty;
            if (createPfxFile)
            {
                log?.Invoke("[CERT] Building PFX certificate file...");
                var pfxBytes = BuildPfxBytes(cert, privateKey, domains[0], leafCertificatePem, privateKeyPem, log);

                pfxPath = Path.Join(certificateOutputDirectory, "certificate.pfx");
                log?.Invoke($"[CERT] Saving PFX to: {pfxPath}");
                File.WriteAllBytes(pfxPath, pfxBytes);
                log?.Invoke("[CERT] PFX file saved successfully");
            }

            var expires = GetCertificateNotAfterUtc(leafCertificatePem);
            log?.Invoke($"[CERT] Certificate NotAfter (UTC): {expires:yyyy-MM-dd HH:mm:ss}");

            log?.Invoke("[ACME] ✅ Certificate issuance completed successfully");
            return new CertificateModel
            {
                Domain = string.Join(", ", domains),
                Expires = expires,
                Status = "Valid",
                PfxPath = pfxPath,
                OutputDirectory = certificateOutputDirectory,
                CertificatePemPath = pemPaths.CertPemPath,
                ChainPemPath = pemPaths.ChainPemPath,
                FullChainPemPath = pemPaths.FullChainPemPath,
                PrivateKeyPemPath = pemPaths.KeyPemPath,
                AcmeDirectoryUrl = acmeUrl,
                ValidationMethod = FormatValidationMethod(validationMethod)
            };
        }

        internal static string FormatValidationMethod(ChallengeValidationMethod validationMethod)
        {
            return validationMethod switch
            {
                ChallengeValidationMethod.Http01 => "HTTP-01",
                ChallengeValidationMethod.TlsAlpn01 => "TLS-ALPN-01",
                _ => "DNS-01"
            };
        }

        internal static CertificateKeyAlgorithm ParseKeyAlgorithm(string? raw)
        {
            if (Enum.TryParse<CertificateKeyAlgorithm>(raw, ignoreCase: true, out var parsed))
            {
                return parsed;
            }

            return CertificateKeyAlgorithm.RS256;
        }

        internal static KeyAlgorithm ToCertesKeyAlgorithm(CertificateKeyAlgorithm algorithm)
        {
            return algorithm switch
            {
                CertificateKeyAlgorithm.ES256 => KeyAlgorithm.ES256,
                CertificateKeyAlgorithm.ES384 => KeyAlgorithm.ES384,
                _ => KeyAlgorithm.RS256
            };
        }

        /// <summary>
        /// Parses the leaf certificate PEM and returns its NotAfter timestamp in UTC.
        /// Falls back to UtcNow+90 days only if the PEM cannot be parsed.
        /// </summary>
        internal static DateTime GetCertificateNotAfterUtc(string leafCertificatePem)
        {
            try
            {
                using var certificate = X509Certificate2.CreateFromPem(leafCertificatePem);
                return DateTime.SpecifyKind(certificate.NotAfter.ToUniversalTime(), DateTimeKind.Utc);
            }
            catch (CryptographicException)
            {
                return DateTime.UtcNow.AddDays(90);
            }
            catch (ArgumentException)
            {
                return DateTime.UtcNow.AddDays(90);
            }
        }

        private static async Task HandleTlsAuthorizationAsync(
            IChallengeContext challenge,
            IAuthorizationContext authz,
            string identifier,
            Action<string>? log)
        {
            log?.Invoke("[TLS-ALPN-01] Starting temporary TLS challenge server on port 443...");
            using var challengeCertificate = CreateTlsAlpnChallengeCertificate(identifier, challenge.KeyAuthz);
            using var server = new TlsAlpnChallengeServer(challengeCertificate);
            if (server.IsIpv4Fallback)
            {
                log?.Invoke("[TLS-ALPN-01] Warning: IPv6 is not available on this system; listening on IPv4 only. " +
                            "Validation will fail if the ACME server connects over IPv6.");
            }
            server.Start();

            log?.Invoke("[TLS-ALPN-01] TLS challenge server started, sending challenge validation request...");
            await challenge.Validate();
            log?.Invoke("[TLS-ALPN-01] Waiting for ACME server to verify challenge...");
            await WaitForAuthorizationValidAsync(authz);
            log?.Invoke("[TLS-ALPN-01] Challenge validated successfully, stopping server...");
            server.Stop();
            log?.Invoke("[TLS-ALPN-01] TLS-ALPN challenge completed");
        }

        private static X509Certificate2 CreateTlsAlpnChallengeCertificate(string domain, string keyAuthorization)
        {
            var keyAuthorizationHash = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthorization));
            var acmeIdentifierExtensionBytes = new byte[2 + keyAuthorizationHash.Length];
            acmeIdentifierExtensionBytes[0] = 0x04;
            acmeIdentifierExtensionBytes[1] = (byte)keyAuthorizationHash.Length;
            Buffer.BlockCopy(keyAuthorizationHash, 0, acmeIdentifierExtensionBytes, 2, keyAuthorizationHash.Length);

            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest($"CN={domain}", ecdsa, HashAlgorithmName.SHA256);
            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            subjectAlternativeNames.AddDnsName(domain);

            request.CertificateExtensions.Add(subjectAlternativeNames.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.31", acmeIdentifierExtensionBytes, true));

            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
            var notAfter = DateTimeOffset.UtcNow.AddHours(6);
            using var issued = request.CreateSelfSigned(notBefore, notAfter);
            var exported = issued.Export(X509ContentType.Pfx);

            return X509CertificateLoader.LoadPkcs12(
                exported,
                (string?)null,
                X509KeyStorageFlags.EphemeralKeySet);
            }

        private static async Task HandleHttpAuthorizationAsync(
            IChallengeContext challenge,
            IAuthorizationContext authz,
            string identifier,
            HttpChallengeDeploymentOptions? options,
            Action<string>? log)
        {
            var effectiveOptions = options ?? new HttpChallengeDeploymentOptions();

            if (effectiveOptions.Method == HttpChallengeDeploymentMethod.SelfHosted)
            {
                log?.Invoke("[HTTP-01] Starting HTTP challenge server on port 80...");
                using var server = new HttpChallengeServer(challenge.Token, challenge.KeyAuthz);
                server.Start();
                log?.Invoke("[HTTP-01] HTTP server started, sending challenge validation request...");
                await challenge.Validate();
                log?.Invoke("[HTTP-01] Waiting for ACME server to verify challenge...");
                await WaitForAuthorizationValidAsync(authz);
                log?.Invoke("[HTTP-01] Challenge validated successfully, stopping server...");
                server.Stop();
                log?.Invoke("[HTTP-01] HTTP challenge completed");
                return;
            }

            var deploymentKey = await DeployHttpChallengeAsync(challenge.Token, challenge.KeyAuthz, identifier, effectiveOptions, log);
            try
            {
                await ProbeHttpChallengeAsync(identifier, challenge.Token, challenge.KeyAuthz, effectiveOptions, log);
                log?.Invoke("[HTTP-01] Sending challenge validation request...");
                await challenge.Validate();
                log?.Invoke("[HTTP-01] Waiting for ACME server to verify challenge...");
                await WaitForAuthorizationValidAsync(authz);
                log?.Invoke("[HTTP-01] Challenge validated successfully");
            }
            finally
            {
                try
                {
                    await CleanupHttpChallengeAsync(challenge.Token, challenge.KeyAuthz, identifier, effectiveOptions, deploymentKey, log);
                }
                catch (HttpRequestException ex)
                {
                    log?.Invoke($"[HTTP-01] Cleanup warning: {ex.Message}");
                }
                catch (IOException ex)
                {
                    log?.Invoke($"[HTTP-01] Cleanup warning: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    log?.Invoke($"[HTTP-01] Cleanup warning: {ex.Message}");
                }
                catch (System.Security.SecurityException ex)
                {
                    log?.Invoke($"[HTTP-01] Cleanup warning: {ex.Message}");
                }
            }
        }

        private static async Task<string> DeployHttpChallengeAsync(
            string token,
            string keyAuthorization,
            string identifier,
            HttpChallengeDeploymentOptions options,
            Action<string>? log)
        {
            switch (options.Method)
            {
                case HttpChallengeDeploymentMethod.NetworkPath:
                    EnsureRequiredTarget(options.Target, "network path");
                    System.IO.Directory.CreateDirectory(options.Target);
                    var path = Path.Join(options.Target, token);
                    await File.WriteAllTextAsync(path, keyAuthorization + Environment.NewLine);
                    log?.Invoke($"[HTTP-01] Challenge file written to network/local path: {path}");
                    return path;

                case HttpChallengeDeploymentMethod.Ftp:
                    EnsureRequiredTarget(options.Target, "FTP target URL");
                    var ftpUri = EnsureUri(options.Target, "ftp");
                    var ftpUsername = ResolveUsername(options, ftpUri, "anonymous");
                    var ftpPassword = ResolvePassword(options, ftpUri);
                    var ftpDirectory = string.IsNullOrWhiteSpace(ftpUri.AbsolutePath) ? "/" : ftpUri.AbsolutePath;
                    var ftpUrl = CombineUrl(options.Target, token);
                    var ftpRemotePath = CombineSftpPath(ftpDirectory, token);
                    var ftpPayload = Encoding.UTF8.GetBytes(keyAuthorization + Environment.NewLine);

                    await using (var ftpClient = new AsyncFtpClient(ftpUri.Host, ftpUsername, ftpPassword, ftpUri.Port > 0 ? ftpUri.Port : 21))
                    {
                        await ftpClient.Connect();
                        await ftpClient.UploadBytes(ftpPayload, ftpRemotePath, createRemoteDir: true, token: CancellationToken.None);
                        await ftpClient.Disconnect();
                    }

                    log?.Invoke($"[HTTP-01] Uploaded challenge file over FTP: {ftpUrl}");
                    return ftpUrl;

                case HttpChallengeDeploymentMethod.Sftp:
                    EnsureRequiredTarget(options.Target, "SFTP target URL");
                    EnsureRequiredCredentials(options, "SFTP");
                    var sftpUri = EnsureUri(options.Target, "sftp");
                    var remoteDirectory = string.IsNullOrWhiteSpace(sftpUri.AbsolutePath) ? "/" : sftpUri.AbsolutePath;
                    var remoteFilePath = CombineSftpPath(remoteDirectory, token);

                    await Task.Run(() =>
                    {
                        using var client = new SftpClient(sftpUri.Host, sftpUri.Port > 0 ? sftpUri.Port : 22, options.Username, options.Password);
                        client.Connect();
                        EnsureSftpDirectoryExists(client, remoteDirectory);
                        using var payload = new MemoryStream(Encoding.UTF8.GetBytes(keyAuthorization + Environment.NewLine));
                        client.UploadFile(payload, remoteFilePath, true);
                        client.Disconnect();
                    });

                    log?.Invoke($"[HTTP-01] Uploaded challenge file over SFTP: {remoteFilePath}");
                    return remoteFilePath;

                case HttpChallengeDeploymentMethod.WebDav:
                    EnsureRequiredTarget(options.Target, "WebDav target URL");
                    var webDavUrl = CombineUrl(options.Target, token);
                    {
                        var client = AcmeHttpClientFactory.GetClient(options.SkipTlsCertificateValidation);
                        using var content = new StringContent(keyAuthorization + Environment.NewLine, Encoding.UTF8, "text/plain");
                        using var request = new HttpRequestMessage(HttpMethod.Put, webDavUrl) { Content = content };
                        ApplyHttpAuthentication(request, options);
                        using var response = await client.SendAsync(request);
                        response.EnsureSuccessStatusCode();
                    }

                    log?.Invoke($"[HTTP-01] Uploaded challenge file over WebDav: {webDavUrl}");
                    return webDavUrl;

                case HttpChallengeDeploymentMethod.Rest:
                    EnsureRequiredTarget(options.Target, "REST endpoint URL");
                    await SendRestChallengeRequestAsync(options, "present", token, keyAuthorization, identifier);
                    log?.Invoke($"[HTTP-01] Presented challenge via REST endpoint: {options.Target}");
                    return options.Target;

                default:
                    throw new InvalidOperationException($"Unsupported HTTP deployment method '{options.Method}'.");
            }
        }

        private static async Task CleanupHttpChallengeAsync(
            string token,
            string keyAuthorization,
            string identifier,
            HttpChallengeDeploymentOptions options,
            string deploymentKey,
            Action<string>? log)
        {
            switch (options.Method)
            {
                case HttpChallengeDeploymentMethod.NetworkPath:
                    if (File.Exists(deploymentKey))
                    {
                        File.Delete(deploymentKey);
                    }

                    log?.Invoke("[HTTP-01] Removed challenge file from network/local path");
                    break;

                case HttpChallengeDeploymentMethod.Ftp:
                    EnsureRequiredTarget(options.Target, "FTP target URL");
                    var ftpUri = EnsureUri(options.Target, "ftp");
                    var ftpUsername = ResolveUsername(options, ftpUri, "anonymous");
                    var ftpPassword = ResolvePassword(options, ftpUri);
                    var ftpDirectory = string.IsNullOrWhiteSpace(ftpUri.AbsolutePath) ? "/" : ftpUri.AbsolutePath;
                    var ftpRemotePath = CombineSftpPath(ftpDirectory, token);

                    await using (var ftpClient = new AsyncFtpClient(ftpUri.Host, ftpUsername, ftpPassword, ftpUri.Port > 0 ? ftpUri.Port : 21))
                    {
                        await ftpClient.Connect();
                        if (await ftpClient.FileExists(ftpRemotePath, CancellationToken.None))
                        {
                            await ftpClient.DeleteFile(ftpRemotePath, CancellationToken.None);
                        }

                        await ftpClient.Disconnect();
                    }

                    log?.Invoke("[HTTP-01] Removed challenge file from FTP target");
                    break;

                case HttpChallengeDeploymentMethod.Sftp:
                    EnsureRequiredTarget(options.Target, "SFTP target URL");
                    EnsureRequiredCredentials(options, "SFTP");
                    var sftpUri = EnsureUri(options.Target, "sftp");
                    await Task.Run(() =>
                    {
                        using var client = new SftpClient(sftpUri.Host, sftpUri.Port > 0 ? sftpUri.Port : 22, options.Username, options.Password);
                        client.Connect();
                        if (client.Exists(deploymentKey))
                        {
                            client.DeleteFile(deploymentKey);
                        }

                        client.Disconnect();
                    });

                    log?.Invoke("[HTTP-01] Removed challenge file from SFTP target");
                    break;

                case HttpChallengeDeploymentMethod.WebDav:
                    {
                        var client = AcmeHttpClientFactory.GetClient(options.SkipTlsCertificateValidation);
                        using var request = new HttpRequestMessage(HttpMethod.Delete, deploymentKey);
                        ApplyHttpAuthentication(request, options);
                        using var response = await client.SendAsync(request);
                        if (response.StatusCode != HttpStatusCode.NotFound)
                        {
                            response.EnsureSuccessStatusCode();
                        }
                    }

                    log?.Invoke("[HTTP-01] Removed challenge file from WebDav target");
                    break;

                case HttpChallengeDeploymentMethod.Rest:
                    await SendRestChallengeRequestAsync(options, "cleanup", token, keyAuthorization, identifier);
                    log?.Invoke("[HTTP-01] Cleanup request sent to REST endpoint");
                    break;
            }
        }

        private static async Task ProbeHttpChallengeAsync(
            string identifier,
            string token,
            string keyAuthorization,
            HttpChallengeDeploymentOptions options,
            Action<string>? log)
        {
            if (string.IsNullOrWhiteSpace(options.PublicValidationUrlTemplate))
            {
                return;
            }

            var probeUrl = BuildProbeUrl(options.PublicValidationUrlTemplate, identifier, token);

            try
            {
                var client = AcmeHttpClientFactory.GetClient(skipTlsValidation: false);
                using var response = await client.GetAsync(probeUrl);
                var content = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode &&
                    string.Equals(content.Trim(), keyAuthorization.Trim(), StringComparison.Ordinal))
                {
                    log?.Invoke($"[HTTP-01] Probe succeeded at {probeUrl}");
                }
                else
                {
                    log?.Invoke($"[HTTP-01] Probe warning at {probeUrl}: status {(int)response.StatusCode}");
                }
            }
            catch (HttpRequestException ex)
            {
                log?.Invoke($"[HTTP-01] Probe warning: {ex.Message}");
            }
            catch (TaskCanceledException ex)
            {
                log?.Invoke($"[HTTP-01] Probe warning: {ex.Message}");
            }
            catch (IOException ex)
            {
                log?.Invoke($"[HTTP-01] Probe warning: {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                log?.Invoke($"[HTTP-01] Probe warning: {ex.Message}");
            }
            catch (System.Security.SecurityException ex)
            {
                log?.Invoke($"[HTTP-01] Probe warning: {ex.Message}");
            }
        }

        private static async Task SendRestChallengeRequestAsync(
            HttpChallengeDeploymentOptions options,
            string action,
            string token,
            string keyAuthorization,
            string identifier)
        {
            var client = AcmeHttpClientFactory.GetClient(options.SkipTlsCertificateValidation);

            var method = string.IsNullOrWhiteSpace(options.RestMethod) ? "POST" : options.RestMethod;
            using var request = new HttpRequestMessage(new HttpMethod(method), options.Target)
            {
                Content = new StringContent(BuildRestPayloadJson(action, identifier, token, keyAuthorization), Encoding.UTF8, "application/json")
            };

            ApplyHttpAuthentication(request, options);

            if (!string.IsNullOrWhiteSpace(options.AdditionalHeaderName) &&
                !string.IsNullOrWhiteSpace(options.AdditionalHeaderValue))
            {
                request.Headers.TryAddWithoutValidation(options.AdditionalHeaderName, options.AdditionalHeaderValue);
            }

            using var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        /// <summary>
        /// Applies authentication headers to a single request so shared HttpClient instances
        /// are not mutated with per-call credentials.
        /// </summary>
        private static void ApplyHttpAuthentication(HttpRequestMessage request, HttpChallengeDeploymentOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.BearerToken))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", options.BearerToken);
                return;
            }

            if (!string.IsNullOrWhiteSpace(options.Username) || !string.IsNullOrWhiteSpace(options.Password))
            {
                var raw = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.Username}:{options.Password}"));
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", raw);
            }
        }

        private static string CombineUrl(string baseUrl, string segment)
        {
            return $"{baseUrl.TrimEnd('/')}/{segment}";
        }

        internal static HttpChallengeDeploymentMethod ParseHttpDeploymentMethod(string? raw)
        {
            if (Enum.TryParse<HttpChallengeDeploymentMethod>(raw, ignoreCase: true, out var parsed))
            {
                return parsed;
            }

            return HttpChallengeDeploymentMethod.SelfHosted;
        }

        internal static bool IsStagingDirectoryUrl(string acmeUrl)
        {
            return acmeUrl.Contains("staging", StringComparison.OrdinalIgnoreCase);
        }

        internal static string BuildProbeUrl(string template, string domain, string token)
        {
            return template
                .Replace("{domain}", domain, StringComparison.OrdinalIgnoreCase)
                .Replace("{token}", token, StringComparison.OrdinalIgnoreCase);
        }

        internal static string BuildRestPayloadJson(string action, string domain, string token, string keyAuthorization)
        {
            return JsonSerializer.Serialize(new
            {
                action,
                domain,
                token,
                keyAuthorization,
                relativePath = $"/.well-known/acme-challenge/{token}"
            });
        }

        private static string CombineSftpPath(string directory, string segment)
        {
            var trimmed = directory.TrimEnd('/');
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                return $"/{segment}";
            }

            return $"{trimmed}/{segment}";
        }

        private static Uri EnsureUri(string url, string expectedScheme)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, expectedScheme, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Expected a valid {expectedScheme.ToUpperInvariant()} URL, but got '{url}'.");
            }

            return uri;
        }

        private static void EnsureRequiredTarget(string target, string targetDescription)
        {
            if (string.IsNullOrWhiteSpace(target))
            {
                throw new InvalidOperationException($"HTTP-01 {targetDescription} is required for this deployment method.");
            }
        }

        private static void EnsureRequiredCredentials(HttpChallengeDeploymentOptions options, string protocol)
        {
            if (string.IsNullOrWhiteSpace(options.Username) || string.IsNullOrWhiteSpace(options.Password))
            {
                throw new InvalidOperationException($"{protocol} deployment requires username and password.");
            }
        }

        private static string ResolveUsername(HttpChallengeDeploymentOptions options, Uri uri, string defaultValue)
        {
            if (!string.IsNullOrWhiteSpace(options.Username))
            {
                return options.Username;
            }

            if (!string.IsNullOrWhiteSpace(uri.UserInfo))
            {
                return Uri.UnescapeDataString(uri.UserInfo.Split(':', 2)[0]);
            }

            return defaultValue;
        }

        private static string ResolvePassword(HttpChallengeDeploymentOptions options, Uri uri)
        {
            if (!string.IsNullOrWhiteSpace(options.Password))
            {
                return options.Password;
            }

            if (!string.IsNullOrWhiteSpace(uri.UserInfo))
            {
                var parts = uri.UserInfo.Split(':', 2);
                if (parts.Length == 2)
                {
                    return Uri.UnescapeDataString(parts[1]);
                }
            }

            return string.Empty;
        }

        private static void EnsureSftpDirectoryExists(SftpClient client, string fullPath)
        {
            if (string.IsNullOrWhiteSpace(fullPath) || fullPath == "/")
            {
                return;
            }

            var segments = fullPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var current = "/";
            foreach (var segment in segments)
            {
                current = CombineSftpPath(current, segment);
                if (!client.Exists(current))
                {
                    client.CreateDirectory(current);
                }
            }
        }

        public async Task RevokeCertificateAsync(CertificateModel certificate)
        {
            var acmeUrl = string.IsNullOrWhiteSpace(certificate.AcmeDirectoryUrl)
                ? LetsEncryptProductionDirectoryUrl
                : certificate.AcmeDirectoryUrl;

            var rawCertificate = LoadCertificateForRevocation(certificate);

            // ACME revocation (Let's Encrypt) requires the certificate's own private key to sign the request.
            // The account key is not sufficient for standard revocation.
            string? privateKeyPem = null;
            try
            {
                privateKeyPem = GetPrivateKeyPemForRevocation(certificate);
            }
            catch (InvalidOperationException)
            {
                // No private key available; we cannot perform ACME revocation.
                throw new InvalidOperationException(
                    "Revocation requires the certificate's private key (privkey.pem). " +
                    "The certificate can be deleted locally, but ACME server revocation cannot be performed without the private key.");
            }

            // Create a fresh AcmeContext without an account key; the private key will be used only for the revocation signature.
            var acme = new AcmeContext(new Uri(acmeUrl));
            var certPrivateKey = KeyFactory.FromPem(privateKeyPem);

            try
            {
                await acme.RevokeCertificate(rawCertificate, RevocationReason.CessationOfOperation, certPrivateKey);
            }
            catch (AcmeRequestException ex)
            {
                var detail = ex.Error?.Detail ?? ex.Message;
                throw new InvalidOperationException($"ACME server rejected revocation request: {detail}", ex);
            }
        }

        private static byte[] LoadCertificateForRevocation(CertificateModel certificate)
        {
            if (!string.IsNullOrWhiteSpace(certificate.PfxPath) && File.Exists(certificate.PfxPath))
            {
                using var cert = X509CertificateLoader.LoadPkcs12FromFile(
                    certificate.PfxPath,
                    (string?)null,
                    X509KeyStorageFlags.EphemeralKeySet);
                return cert.Export(X509ContentType.Cert);
            }

            if (!string.IsNullOrWhiteSpace(certificate.CertificatePemPath) && File.Exists(certificate.CertificatePemPath))
            {
                using var cert = X509Certificate2.CreateFromPemFile(certificate.CertificatePemPath);
                return cert.Export(X509ContentType.Cert);
            }

            throw new FileNotFoundException(
                "Cannot revoke because certificate file is missing. Expected either certificate.pfx or cert.pem in the certificate output folder.");
        }

        private static string GetPrivateKeyPemForRevocation(CertificateModel certificate)
        {
            if (!string.IsNullOrWhiteSpace(certificate.PrivateKeyPemPath) && File.Exists(certificate.PrivateKeyPemPath))
            {
                return File.ReadAllText(certificate.PrivateKeyPemPath).Trim();
            }

            if (!string.IsNullOrWhiteSpace(certificate.PfxPath) && File.Exists(certificate.PfxPath))
            {
                throw new InvalidOperationException(
                    "Private key PEM path missing. " +
                    "Revocation requires privkey.pem. PFX fallback key export is not supported; ensure privkey.pem exists alongside the certificate.");
            }

            throw new InvalidOperationException("Private key not found for revocation. Expected privkey.pem in certificate folder.");
        }

        private static string ComputeDnsTxtValue(string keyAuthorization)
        {
            var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(keyAuthorization));
            return Base64UrlEncode(hash);
        }

        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static bool IsIssuerResolutionFailure(Exception ex)
        {
            return ex.Message.Contains("Can not find issuer", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("Cannot find issuer", StringComparison.OrdinalIgnoreCase);
        }

        private static TimeSpan GetDnsPropagationDelay(IReadOnlyDictionary<string, string> credentials)
        {
            if (!credentials.TryGetValue("propagationSeconds", out var value) || string.IsNullOrWhiteSpace(value))
            {
                return TimeSpan.FromSeconds(30);
            }

            if (int.TryParse(value, out var seconds) && seconds >= 0 && seconds <= 3600)
            {
                return TimeSpan.FromSeconds(seconds);
            }

            return TimeSpan.FromSeconds(30);
        }

        private static async Task<string> BuildOrderFailureDetailsAsync(IOrderContext order)
        {
            try
            {
                var orderResource = await order.Resource();
                var parts = new List<string>
                {
                    $"Order status: {orderResource.Status}."
                };

                if (orderResource.Error is not null)
                {
                    parts.Add($"Order error: {FormatAcmeError(orderResource.Error)}");
                }

                var authorizations = await order.Authorizations();
                var authorizationResources = await Task.WhenAll(authorizations.Select(authz => authz.Resource()));
                foreach (var authzResource in authorizationResources)
                {
                    var authzPart = $"Authorization '{authzResource.Identifier?.Value}' status: {authzResource.Status}.";
                    var invalidChallengeError = authzResource.Challenges?
                        .Select(challenge => challenge.Status == ChallengeStatus.Invalid ? challenge.Error : null)
                        .FirstOrDefault(error => error is not null);

                    if (invalidChallengeError is not null)
                    {
                        authzPart += $" Challenge error: {FormatAcmeError(invalidChallengeError)}";
                    }

                    parts.Add(authzPart);
                }

                return string.Join(" ", parts);
            }
            catch (Exception ex) when (
                ex is AcmeRequestException ||
                ex is HttpRequestException ||
                ex is IOException ||
                ex is CryptographicException ||
                ex is InvalidOperationException)
            {
                return $"Unable to fetch detailed order diagnostics from ACME server. Reason: {ex.Message}";
            }
        }

        private static byte[] BuildLeafOnlyPfx(string leafCertificatePem, string privateKeyPem)
        {
            using var certificateWithKey = X509Certificate2.CreateFromPem(leafCertificatePem, privateKeyPem);
            return certificateWithKey.Export(X509ContentType.Pfx);
        }

        /// <summary>
        /// Builds a PFX from the Certes certificate chain. When Certes cannot resolve intermediate/root
        /// issuers (common with staging chains), falls back to a leaf-only PFX export.
        /// </summary>
        private static byte[] BuildPfxBytes(
            CertificateChain certificateChain,
            IKey privateKey,
            string friendlyName,
            string leafCertificatePem,
            string privateKeyPem,
            Action<string>? log)
        {
            try
            {
                var pfxBytes = certificateChain.ToPfx(privateKey).Build(friendlyName, null);
                log?.Invoke("[CERT] PFX file built successfully");
                return pfxBytes;
            }
            catch (Exception ex) when (
                ex is CryptographicException ||
                ex is InvalidOperationException ||
                ex is AcmeException ||
                IsIssuerResolutionFailure(ex))
            {
                log?.Invoke($"[CERT] ⚠️ PFX build failed ({ex.GetType().Name}: {ex.Message}). Falling back to leaf-only PFX export.");
                var fallback = BuildLeafOnlyPfx(leafCertificatePem, privateKeyPem);
                log?.Invoke("[CERT] Fallback PFX created (leaf certificate only)");
                return fallback;
            }
        }

        private static string TryGetFullChainPem(CertificateChain certificateChain, string leafCertificatePem, Action<string>? log)
        {
            try
            {
                return certificateChain.ToPem();
            }
            catch (Exception ex) when (IsIssuerResolutionFailure(ex))
            {
                log?.Invoke("Could not export full chain PEM due to issuer resolution. Saving leaf PEM only for fullchain artifact.");
                return leafCertificatePem;
            }
        }

        private static PemArtifactPaths SavePemArtifacts(string outputDirectory, string leafCertificatePem, string fullChainPem, string privateKeyPem, Action<string>? log)
        {
            var certificates = SplitCertificatesPem(fullChainPem);
            if (certificates.Count == 0)
            {
                certificates.Add(leafCertificatePem);
            }

            var certPemPath = Path.Join(outputDirectory, "cert.pem");
            var chainPemPath = Path.Join(outputDirectory, "chain.pem");
            var fullchainPemPath = Path.Join(outputDirectory, "fullchain.pem");
            var keyPemPath = Path.Join(outputDirectory, "privkey.pem");

            File.WriteAllText(certPemPath, leafCertificatePem.Trim() + Environment.NewLine);
            File.WriteAllText(fullchainPemPath, string.Join(Environment.NewLine + Environment.NewLine, certificates) + Environment.NewLine);

            if (certificates.Count > 1)
            {
                var chainOnly = certificates.Skip(1).ToArray();
                File.WriteAllText(chainPemPath, string.Join(Environment.NewLine + Environment.NewLine, chainOnly) + Environment.NewLine);
            }
            else
            {
                File.WriteAllText(chainPemPath, string.Empty);
            }

            File.WriteAllText(keyPemPath, privateKeyPem.Trim() + Environment.NewLine);
            log?.Invoke($"Saved PEM artifacts: {Path.GetFileName(certPemPath)}, {Path.GetFileName(fullchainPemPath)}, {Path.GetFileName(chainPemPath)}, {Path.GetFileName(keyPemPath)}");
            return new PemArtifactPaths(certPemPath, chainPemPath, fullchainPemPath, keyPemPath);
        }

        private static string GetCertificateOutputDirectory(string domain)
        {
            var normalizedFolder = domain.Trim();
            if (normalizedFolder.StartsWith("*.", StringComparison.Ordinal))
            {
                normalizedFolder = $"wildcard.{normalizedFolder[2..]}";
            }

            normalizedFolder = normalizedFolder.Replace('*', '_');
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitizedChars = normalizedFolder
                .Select(ch => invalidChars.Contains(ch) ? '_' : ch)
                .ToArray();

            var sanitized = new string(sanitizedChars).Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(sanitized))
            {
                sanitized = "certificate";
            }

            if (ReservedWindowsFileNames.Contains(sanitized))
            {
                sanitized += "_cert";
            }

            return Path.Join(RuntimePaths.CertsDirectory, sanitized);
        }

        private readonly record struct PemArtifactPaths(
            string CertPemPath,
            string ChainPemPath,
            string FullChainPemPath,
            string KeyPemPath);

        private static List<string> SplitCertificatesPem(string pemChain)
        {
            const string beginMarker = "-----BEGIN CERTIFICATE-----";
            const string endMarker = "-----END CERTIFICATE-----";

            var results = new List<string>();
            var cursor = 0;

            while (true)
            {
                var begin = pemChain.IndexOf(beginMarker, cursor, StringComparison.Ordinal);
                if (begin < 0)
                {
                    break;
                }

                var end = pemChain.IndexOf(endMarker, begin, StringComparison.Ordinal);
                if (end < 0)
                {
                    break;
                }

                end += endMarker.Length;
                results.Add(pemChain[begin..end]);
                cursor = end;
            }

            return results;
        }

        private static string FormatAcmeError(object error)
        {
            var errorType = error.GetType();
            var typeProp = errorType.GetProperty("Type");
            var detailProp = errorType.GetProperty("Detail");
            var statusProp = errorType.GetProperty("Status");

            var typeValue = typeProp?.GetValue(error)?.ToString();
            var detailValue = detailProp?.GetValue(error)?.ToString();
            var statusValue = statusProp?.GetValue(error)?.ToString();

            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(typeValue))
            {
                parts.Add(typeValue);
            }

            if (!string.IsNullOrWhiteSpace(detailValue))
            {
                parts.Add(detailValue);
            }

            if (!string.IsNullOrWhiteSpace(statusValue))
            {
                parts.Add($"status={statusValue}");
            }

            return parts.Count == 0 ? error.ToString() ?? "Unknown ACME error" : string.Join(" | ", parts);
        }

        private static async Task WaitForAuthorizationValidAsync(IAuthorizationContext authz)
        {
            var deadline = DateTimeOffset.UtcNow + MaxWaitForAuthorization;

            while (DateTimeOffset.UtcNow < deadline)
            {
                var resource = await authz.Resource();
                var status = resource.Status;

                if (status == Certes.Acme.Resource.AuthorizationStatus.Valid)
                {
                    return;
                }

                if (status == Certes.Acme.Resource.AuthorizationStatus.Invalid ||
                    status == Certes.Acme.Resource.AuthorizationStatus.Deactivated ||
                    status == Certes.Acme.Resource.AuthorizationStatus.Expired ||
                    status == Certes.Acme.Resource.AuthorizationStatus.Revoked)
                {
                    throw new InvalidOperationException(
                        $"Authorization for '{resource.Identifier?.Value}' failed with status '{status}'.");
                }

                await Task.Delay(GetPollDelay(authz.RetryAfter));
            }

            throw new TimeoutException("Timed out waiting for domain authorization to become valid.");
        }

        private static async Task WaitForOrderReadyAsync(IOrderContext order)
        {
            var deadline = DateTimeOffset.UtcNow + MaxWaitForOrderReady;

            while (DateTimeOffset.UtcNow < deadline)
            {
                var resource = await order.Resource();
                var status = resource.Status;

                if (status == Certes.Acme.Resource.OrderStatus.Ready ||
                    status == Certes.Acme.Resource.OrderStatus.Valid)
                {
                    return;
                }

                if (status == Certes.Acme.Resource.OrderStatus.Invalid)
                {
                    throw new InvalidOperationException("ACME order became invalid before finalization.");
                }

                await Task.Delay(GetPollDelay(order.RetryAfter));
            }

            throw new TimeoutException("Timed out waiting for ACME order to become ready for finalization.");
        }

        /// <summary>
        /// Loads order authorizations with a short retry for transient ACME resource fetch failures.
        /// Certes Authorizations() always re-POSTs the order resource.
        /// </summary>
        private static async Task<IEnumerable<IAuthorizationContext>> LoadOrderAuthorizationsAsync(
            IOrderContext order,
            Action<string>? log)
        {
            const int maxAttempts = 4;
            Exception? lastError = null;

            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    return await order.Authorizations();
                }
                catch (AcmeRequestException ex) when (attempt < maxAttempts && IsTransientAcmeRequestFailure(ex))
                {
                    lastError = ex;
                    var delay = TimeSpan.FromSeconds(attempt * 2);
                    log?.Invoke(
                        $"[ACME] Transient failure loading order authorizations " +
                        $"(attempt {attempt}/{maxAttempts}): {FormatAcmeException(ex)}. Retrying in {delay.TotalSeconds:0}s...");
                    await Task.Delay(delay);
                }
            }

            throw lastError ?? new InvalidOperationException("Failed to load ACME order authorizations.");
        }

        private static bool IsTransientAcmeRequestFailure(AcmeRequestException ex)
        {
            // Certes wraps many HTTP/ACME failures as "Fail to load resource from '{url}'.".
            // Retry on rate limits, server errors, and generic resource-load failures without a permanent ACME type.
            var status = ex.Error?.Status;
            if (status is HttpStatusCode.TooManyRequests or
                HttpStatusCode.RequestTimeout or
                HttpStatusCode.BadGateway or
                HttpStatusCode.ServiceUnavailable or
                HttpStatusCode.GatewayTimeout or
                HttpStatusCode.InternalServerError)
            {
                return true;
            }

            var type = ex.Error?.Type ?? string.Empty;
            if (type.Contains("rateLimited", StringComparison.OrdinalIgnoreCase) ||
                type.Contains("serverInternal", StringComparison.OrdinalIgnoreCase) ||
                type.Contains("badNonce", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Permanent client errors should not be retried.
            if (status is HttpStatusCode.BadRequest or
                HttpStatusCode.Unauthorized or
                HttpStatusCode.Forbidden or
                HttpStatusCode.NotFound or
                HttpStatusCode.Conflict or
                HttpStatusCode.UnsupportedMediaType)
            {
                return false;
            }

            return ex.Message.Contains("Fail to load resource", StringComparison.OrdinalIgnoreCase);
        }

        private static InvalidOperationException CreateAcmeOperationException(string operation, AcmeException ex)
        {
            var details = FormatAcmeException(ex);
            return new InvalidOperationException($"Failed to {operation}. {details}", ex);
        }

        internal static string FormatAcmeException(AcmeException ex)
        {
            if (ex is AcmeRequestException requestEx && requestEx.Error is not null)
            {
                var formatted = FormatAcmeError(requestEx.Error);
                if (!string.IsNullOrWhiteSpace(formatted) &&
                    !string.Equals(formatted, "Unknown ACME error", StringComparison.Ordinal))
                {
                    return $"{ex.Message} ({formatted})";
                }
            }

            if (ex.InnerException is not null && !string.IsNullOrWhiteSpace(ex.InnerException.Message))
            {
                return $"{ex.Message} Inner: {ex.InnerException.Message}";
            }

            return ex.Message;
        }

        /// <summary>
        /// After finalize, the CA may leave the order in Processing until the certificate is issued.
        /// Poll until Valid (or timeout/invalid), then download the certificate chain.
        /// </summary>
        private static async Task<CertificateChain> WaitForOrderValidAndDownloadAsync(
            IOrderContext order,
            Action<string>? log)
        {
            var deadline = DateTimeOffset.UtcNow + MaxWaitForOrderValid;
            var lastLoggedStatus = (OrderStatus?)null;

            while (DateTimeOffset.UtcNow < deadline)
            {
                var resource = await order.Resource();
                var status = resource.Status;

                if (status != lastLoggedStatus)
                {
                    log?.Invoke($"[CERT] Waiting for issued certificate; order status: {status}");
                    lastLoggedStatus = status;
                }

                if (status == OrderStatus.Valid)
                {
                    return await order.Download();
                }

                if (status == OrderStatus.Invalid)
                {
                    var details = await BuildOrderFailureDetailsAsync(order);
                    throw new InvalidOperationException($"ACME order became invalid after finalization. {details}");
                }

                // Ready means not yet finalized; Processing means CA is issuing.
                // Keep polling for both so a late finalize race can still succeed via Download
                // only when Valid. If still Ready, caller already finalized via Generate.
                if (status is not (OrderStatus.Processing or OrderStatus.Ready or OrderStatus.Pending))
                {
                    var details = await BuildOrderFailureDetailsAsync(order);
                    throw new InvalidOperationException($"Unexpected ACME order status while waiting for certificate. {details}");
                }

                await Task.Delay(GetPollDelay(order.RetryAfter));
            }

            var timeoutDetails = await BuildOrderFailureDetailsAsync(order);
            throw new TimeoutException(
                $"Timed out waiting for ACME order to become valid after finalization. {timeoutDetails}");
        }

        private static TimeSpan GetPollDelay(int retryAfterSeconds)
        {
            if (retryAfterSeconds <= 0)
            {
                return DefaultPollDelay;
            }

            var bounded = Math.Min(retryAfterSeconds, 15);
            return TimeSpan.FromSeconds(bounded);
        }
    }

    // Tiny built-in web server for HTTP-01 (runs only during validation)
    public class HttpChallengeServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly string _token;
        private readonly string _keyAuth;
        private bool _running;
        private bool _disposed;
        private Task? _listenerTask;

        public HttpChallengeServer(string token, string keyAuth)
        {
            _token = token;
            _keyAuth = keyAuth;
            _listener.Prefixes.Add("http://+:80/.well-known/acme-challenge/");
        }

        public void Start()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(HttpChallengeServer));
            }

            if (_running)
            {
                return;
            }

            _running = true;
            try
            {
                _listener.Start();
            }
            catch (HttpListenerException ex)
            {
                _running = false;
                throw TranslateListenerStartException(ex);
            }
            _listenerTask = Task.Run(async () =>
            {
                while (_running)
                {
                    HttpListenerContext ctx;
                    try
                    {
                        ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (HttpListenerException)
                    {
                        break;
                    }

                    try
                    {
                        if (ctx.Request.Url?.LocalPath.Contains(_token) == true)
                        {
                            var buffer = System.Text.Encoding.UTF8.GetBytes(_keyAuth);
                            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                            ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
                        }
                        else
                        {
                            ctx.Response.StatusCode = (int)HttpStatusCode.NotFound;
                        }
                    }
                    finally
                    {
                        ctx.Response.Close();
                    }
                }
            });
        }

        /// <summary>
        /// Translates an <see cref="HttpListenerException"/> from listener start into a user-readable
        /// <see cref="InvalidOperationException"/>. Internal so unit tests can exercise error paths.
        /// </summary>
        internal static InvalidOperationException TranslateListenerStartException(HttpListenerException ex)
        {
            // NativeErrorCode 5 = ERROR_ACCESS_DENIED on Windows.
            if (ex.NativeErrorCode == 5 || ex.ErrorCode == 5)
            {
                return new InvalidOperationException(
                    "HTTP-01 validation requires binding to port 80, but access was denied. " +
                    "Run ACMECertManager as Administrator, or reserve URL ACL for your user (example: " +
                    "netsh http add urlacl url=http://+:80/.well-known/acme-challenge/ user=%USERNAME%).", ex);
            }

            // NativeErrorCode 32 / 183 often indicate the prefix or port is already in use.
            if (ex.NativeErrorCode is 32 or 183 ||
                ex.Message.Contains("already", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("conflicts", StringComparison.OrdinalIgnoreCase))
            {
                return new InvalidOperationException(
                    "HTTP-01 validation requires port 80, but the port or URL prefix is already in use by another process.", ex);
            }

            return new InvalidOperationException(
                $"Failed to start HTTP-01 listener on port 80: {ex.Message}", ex);
        }

        public void Stop() => Dispose();
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _running = false;

            if (_listener.IsListening)
            {
                _listener.Stop();
            }

            try
            {
                _listenerTask?.GetAwaiter().GetResult();
            }
            catch (ObjectDisposedException)
            {
                // Expected if the listener was disposed while waiting for a request.
            }
            catch (HttpListenerException)
            {
                // Expected when stopping a listener blocked in GetContextAsync.
            }

            _listener.Close();
            _disposed = true;
        }
    }

    // Tiny built-in TLS server for TLS-ALPN-01 (runs only during validation)
    public class TlsAlpnChallengeServer : IDisposable
    {
        private static readonly SslApplicationProtocol AcmeTlsProtocol = new("acme-tls/1");

        private readonly TcpListener _listener;
        private readonly X509Certificate2 _certificate;
        private bool _running;
        private bool _disposed;
        private Task? _listenerTask;

        // True when IPv6 socket creation failed and the server fell back to IPv4-only.
        public bool IsIpv4Fallback { get; private set; }

        public TlsAlpnChallengeServer(X509Certificate2 certificate)
        {
            _certificate = certificate;
            _listener = CreateListener(out bool ipv4Fallback);
            IsIpv4Fallback = ipv4Fallback;
        }

        // Creates a dual-mode IPv6/IPv4 listener on port 443.
        // Sets ipv4Fallback=true and falls back to IPv4 only when IPv6 is not
        // supported by the OS (AddressFamilyNotSupported). Other SocketExceptions
        // (e.g. access denied, port in use) are not caught here; they propagate
        // from Start() where they are reported with descriptive messages.
        private static TcpListener CreateListener(out bool ipv4Fallback)
        {
            try
            {
                var listener = new TcpListener(IPAddress.IPv6Any, 443);
                listener.Server.DualMode = true;
                ipv4Fallback = false;
                return listener;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressFamilyNotSupported)
            {
                // IPv6 not supported on this system; fall back to IPv4 only.
                ipv4Fallback = true;
                return new TcpListener(IPAddress.Any, 443);
            }
        }

        public void Start()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(TlsAlpnChallengeServer));
            }

            if (_running)
            {
                return;
            }

            _running = true;
            try
            {
                _listener.Start();
            }
            catch (SocketException ex)
            {
                _running = false;
                throw TranslateListenerStartException(ex);
            }

            _listenerTask = Task.Run(async () =>
            {
                var clientTasks = new List<Task>();
                var clientTasksLock = new object();

                try
                {
                    while (_running)
                    {
                        TcpClient? client = null;
                        try
                        {
                            client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                        }
                        catch (ObjectDisposedException)
                        {
                            break;
                        }
                        catch (SocketException)
                        {
                            break;
                        }

                        var clientTask = HandleClientAsync(client);
                        lock (clientTasksLock)
                        {
                            clientTasks.Add(clientTask);
                        }

                        _ = clientTask.ContinueWith(
                            completedTask =>
                            {
                                lock (clientTasksLock)
                                {
                                    clientTasks.Remove(completedTask);
                                }
                            },
                            CancellationToken.None,
                            TaskContinuationOptions.ExecuteSynchronously,
                            TaskScheduler.Default);
                    }
                }
                finally
                {
                    Task[] pendingClientTasks;
                    lock (clientTasksLock)
                    {
                        pendingClientTasks = clientTasks.ToArray();
                    }

                    if (pendingClientTasks.Length > 0)
                    {
                        await Task.WhenAll(pendingClientTasks).ConfigureAwait(false);
                    }
                }
            });
        }

        // Translates a SocketException thrown by TcpListener.Start() into an InvalidOperationException
        // with a user-readable message. Internal so it can be called directly by unit tests.
        internal static InvalidOperationException TranslateListenerStartException(SocketException ex)
        {
            return ex.SocketErrorCode switch
            {
                SocketError.AccessDenied =>
                    new InvalidOperationException(
                        "TLS-ALPN-01 validation requires binding to port 443, but access was denied. " +
                        "Verify that this process is allowed to bind to port 443 and that the port is not blocked by a reservation, excluded port range, local policy, security software, or another process already listening on port 443.", ex),
                SocketError.AddressAlreadyInUse =>
                    new InvalidOperationException(
                        "TLS-ALPN-01 validation requires port 443, but the port is already in use by another process.", ex),
                _ =>
                    new InvalidOperationException(
                        $"Failed to start TLS-ALPN-01 listener on port 443: {ex.Message}", ex)
            };
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                    var options = new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _certificate,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateRequired = false,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                        ApplicationProtocols = new List<SslApplicationProtocol> { AcmeTlsProtocol }
                    };
                    using var handshakeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                    await ssl.AuthenticateAsServerAsync(options, handshakeTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Ignore stalled clients that do not complete the TLS handshake promptly.
                }
                catch (AuthenticationException)
                {
                    // ACME clients may reconnect or abort while probing; no-op.
                }
                catch (IOException)
                {
                    // Ignore client disconnects during challenge probing.
                }
            }
        }

        public void Stop() => Dispose();

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _running = false;

            try
            {
                _listener.Stop();
            }
            catch (ObjectDisposedException)
            {
                // Listener already disposed.
            }

            try
            {
                _listenerTask?.GetAwaiter().GetResult();
            }
            catch (ObjectDisposedException)
            {
                // Expected while tearing down pending accepts.
            }
            catch (SocketException)
            {
                // Expected while tearing down pending accepts.
            }

            _listener.Server.Dispose();
            _certificate.Dispose();
            _disposed = true;
        }
    }
}
