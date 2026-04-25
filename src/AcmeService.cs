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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    public class AcmeService
    {
        public const string LetsEncryptProductionDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";
        public const string LetsEncryptStagingDirectoryUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";

        private static readonly TimeSpan DefaultPollDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxWaitForAuthorization = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan MaxWaitForOrderReady = TimeSpan.FromMinutes(2);
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
            log?.Invoke("[ACME] Account email configured");

            AcmeContext acme;

            // Account bootstrap: load existing key if present, otherwise create a fresh account key.
            if (File.Exists(RuntimePaths.AccountFile))
            {
                log?.Invoke("[ACME] Loading existing account key...");
                var accountKey = KeyFactory.FromPem(File.ReadAllText(RuntimePaths.AccountFile));
                acme = new AcmeContext(new Uri(acmeUrl), accountKey);

                // ACMEv2 servers may require explicit ToS agreement on newAccount.
                // With an existing key this call safely returns the existing account if it already exists.
                await acme.NewAccount(email, true);
                log?.Invoke("[ACME] Account key loaded and verified with ACME server");
            }
            else
            {
                log?.Invoke("[ACME] Creating new ACME account...");
                acme = new AcmeContext(new Uri(acmeUrl));
                await acme.NewAccount(email, true);
                File.WriteAllText(RuntimePaths.AccountFile, acme.AccountKey.ToPem());
                log?.Invoke("[ACME] New account created and persisted");
            }

            log?.Invoke("[ACME] Creating new order with ACME server...");
            var order = await acme.NewOrder(domains);
            log?.Invoke("[ACME] Order created successfully");

            var authorizationIndex = 0;
            foreach (var authz in await order.Authorizations())
            {
                authorizationIndex++;
                log?.Invoke($"[ACME] Processing authorization {authorizationIndex} of {(await order.Authorizations()).Count()}");

                if (validationMethod == ChallengeValidationMethod.Http01)
                {
                    var challenge = await authz.Http();
                    var httpIdentifier = (await authz.Resource()).Identifier?.Value ?? domains[0];
                    await HandleHttpAuthorizationAsync(challenge, authz, httpIdentifier, httpDeployment, log);
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
            log?.Invoke("[CERT] Generating new private key (RS256)...");
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            CertificateChain cert;
            try
            {
                log?.Invoke("[CERT] Creating certificate signing request...");
                cert = await order.Generate(new CsrInfo
                {
                    CommonName = domains[0]
                }, privateKey);
                log?.Invoke("[CERT] Certificate generated successfully from ACME server");
            }
            catch (AcmeException ex)
            {
                var details = await BuildOrderFailureDetailsAsync(order);
                log?.Invoke($"[CERT] ❌ Certificate generation failed: {details}");
                throw new InvalidOperationException($"Fail to finalize order. {details}", ex);
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
                byte[] pfxBytes;
                try
                {
                    pfxBytes = cert.ToPfx(privateKey).Build(domains[0], null);
                    log?.Invoke("[CERT] PFX file built successfully");
                }
                catch (Exception ex) when (IsIssuerResolutionFailure(ex))
                {
                    log?.Invoke("[CERT] ⚠️ Certificate chain issuer resolution failed while building PFX. Falling back to leaf-only PFX export.");
                    pfxBytes = BuildLeafOnlyPfx(leafCertificatePem, privateKeyPem);
                    log?.Invoke("[CERT] Fallback PFX created (leaf certificate only)");
                }

                pfxPath = Path.Join(certificateOutputDirectory, "certificate.pfx");
                log?.Invoke($"[CERT] Saving PFX to: {pfxPath}");
                File.WriteAllBytes(pfxPath, pfxBytes);
                log?.Invoke("[CERT] PFX file saved successfully");
            }

            log?.Invoke("[ACME] ✅ Certificate issuance completed successfully");
            return new CertificateModel
            {
                Domain = string.Join(", ", domains),
                Expires = DateTime.UtcNow.AddDays(90),
                Status = "Valid",
                PfxPath = pfxPath,
                OutputDirectory = certificateOutputDirectory,
                CertificatePemPath = pemPaths.CertPemPath,
                ChainPemPath = pemPaths.ChainPemPath,
                FullChainPemPath = pemPaths.FullChainPemPath,
                PrivateKeyPemPath = pemPaths.KeyPemPath,
                AcmeDirectoryUrl = acmeUrl,
                ValidationMethod = validationMethod == ChallengeValidationMethod.Http01 ? "HTTP-01" : "DNS-01"
            };
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
                    using (var client = CreateHttpClient(options.SkipTlsCertificateValidation))
                    {
                        ApplyHttpAuthentication(client, options);
                        using var content = new StringContent(keyAuthorization + Environment.NewLine, Encoding.UTF8, "text/plain");
                        using var response = await client.PutAsync(webDavUrl, content);
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
                    using (var client = CreateHttpClient(options.SkipTlsCertificateValidation))
                    {
                        ApplyHttpAuthentication(client, options);
                        using var request = new HttpRequestMessage(HttpMethod.Delete, deploymentKey);
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
                using var client = CreateHttpClient(false);
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
            using var client = CreateHttpClient(options.SkipTlsCertificateValidation);
            ApplyHttpAuthentication(client, options);

            if (!string.IsNullOrWhiteSpace(options.AdditionalHeaderName) &&
                !string.IsNullOrWhiteSpace(options.AdditionalHeaderValue))
            {
                client.DefaultRequestHeaders.Remove(options.AdditionalHeaderName);
                client.DefaultRequestHeaders.TryAddWithoutValidation(options.AdditionalHeaderName, options.AdditionalHeaderValue);
            }

            var method = string.IsNullOrWhiteSpace(options.RestMethod) ? "POST" : options.RestMethod;
            using var request = new HttpRequestMessage(new HttpMethod(method), options.Target)
            {
                Content = new StringContent(BuildRestPayloadJson(action, identifier, token, keyAuthorization), Encoding.UTF8, "application/json")
            };

            using var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
        }

        private static void ApplyHttpAuthentication(HttpClient client, HttpChallengeDeploymentOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.BearerToken))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.BearerToken);
                return;
            }

            if (!string.IsNullOrWhiteSpace(options.Username) || !string.IsNullOrWhiteSpace(options.Password))
            {
                var raw = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.Username}:{options.Password}"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", raw);
            }
        }

        private static HttpClient CreateHttpClient(bool skipTlsValidation)
        {
            if (!skipTlsValidation)
            {
                return new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            }

            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = static (_, _, _, _) => true
            };

            return new HttpClient(handler, disposeHandler: true)
            {
                Timeout = TimeSpan.FromSeconds(15)
            };
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
            if (!File.Exists(RuntimePaths.AccountFile))
            {
                throw new InvalidOperationException("ACME account key not found in storage/acme-account.json.");
            }

            var acmeUrl = string.IsNullOrWhiteSpace(certificate.AcmeDirectoryUrl)
                ? LetsEncryptProductionDirectoryUrl
                : certificate.AcmeDirectoryUrl;

            var accountKey = KeyFactory.FromPem(File.ReadAllText(RuntimePaths.AccountFile));
            var acme = new AcmeContext(new Uri(acmeUrl), accountKey);

            var rawCertificate = LoadCertificateForRevocation(certificate);

            await acme.RevokeCertificate(rawCertificate, RevocationReason.CessationOfOperation, null!);
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
            catch (Exception ex)
            {
                return $"Unable to fetch detailed order diagnostics from ACME server. Reason: {ex.Message}";
            }
        }

        private static byte[] BuildLeafOnlyPfx(string leafCertificatePem, string privateKeyPem)
        {
            using var certificateWithKey = X509Certificate2.CreateFromPem(leafCertificatePem, privateKeyPem);
            return certificateWithKey.Export(X509ContentType.Pfx);
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

                if (status == Certes.Acme.Resource.OrderStatus.Ready)
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
            catch (HttpListenerException ex) when (ex.NativeErrorCode == 5)
            {
                _running = false;
                throw new InvalidOperationException(
                    "HTTP-01 validation requires binding to port 80, but access was denied. " +
                    "Run ACMECertManager as Administrator, or reserve URL ACL for your user (example: " +
                    "netsh http add urlacl url=http://+:80/.well-known/acme-challenge/ user=%USERNAME%).", ex);
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
}
