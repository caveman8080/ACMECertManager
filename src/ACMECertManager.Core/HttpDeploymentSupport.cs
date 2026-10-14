using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Renci.SshNet.Common;
using Renci.SshNet.Sftp;

namespace ACMECertManager
{
    /// <summary>
    /// SFTP operations used while publishing an HTTP-01 challenge file.
    /// </summary>
    internal interface ISftpFileSession
    {
        bool Exists(string path);
        void CreateDirectory(string path);
        void UploadFile(Stream input, string path, bool canOverride);
    }

    /// <summary>
    /// Path, port, and SFTP/WebDAV helpers for HTTP-01 deployment.
    /// </summary>
    internal static class HttpDeploymentSupport
    {
        internal const string AcmeChallengeSuffix = ".well-known/acme-challenge";
        internal const string HttpChallengeContentType = "application/octet-stream";

        internal const string SecondaryValidationHint =
            "Let's Encrypt also checks from other regions (secondary validation). " +
            "A firewall or GeoIP country block can stop those validators even when this computer can reach the challenge.";

        internal static string TargetPlaceholder(HttpChallengeDeploymentMethod method)
        {
            return method switch
            {
                HttpChallengeDeploymentMethod.NetworkPath => @"\\server\share\.well-known\acme-challenge or C:\path",
                HttpChallengeDeploymentMethod.Ftp => "ftp://server/path/.well-known/acme-challenge",
                HttpChallengeDeploymentMethod.Sftp => "sftp://server/path/.well-known/acme-challenge",
                HttpChallengeDeploymentMethod.WebDav => "https://server:port/Share/.well-known/acme-challenge",
                HttpChallengeDeploymentMethod.Rest => "https://host/endpoint",
                _ => string.Empty
            };
        }

        internal static string PortPlaceholder(HttpChallengeDeploymentMethod method)
        {
            return method switch
            {
                HttpChallengeDeploymentMethod.Ftp => "21",
                HttpChallengeDeploymentMethod.Sftp => "22",
                HttpChallengeDeploymentMethod.WebDav => "80/443",
                HttpChallengeDeploymentMethod.Rest => "80/443",
                _ => string.Empty
            };
        }

        internal static bool UsesExplicitPort(HttpChallengeDeploymentMethod method)
        {
            return method is HttpChallengeDeploymentMethod.Ftp
                or HttpChallengeDeploymentMethod.Sftp
                or HttpChallengeDeploymentMethod.WebDav
                or HttpChallengeDeploymentMethod.Rest;
        }

        internal static string NormalizeChallengeTarget(HttpChallengeDeploymentMethod method, string? target)
        {
            if (method is not (
                HttpChallengeDeploymentMethod.NetworkPath
                or HttpChallengeDeploymentMethod.Ftp
                or HttpChallengeDeploymentMethod.Sftp
                or HttpChallengeDeploymentMethod.WebDav))
            {
                return target?.Trim() ?? string.Empty;
            }

            var value = target?.Trim() ?? string.Empty;
            if (value.Length == 0)
            {
                return value;
            }

            var trimmed = value.TrimEnd('/', '\\');
            if (EndsWithChallengeSuffix(trimmed))
            {
                return trimmed;
            }

            if (method == HttpChallengeDeploymentMethod.NetworkPath && trimmed.Contains('\\'))
            {
                return trimmed + @"\.well-known\acme-challenge";
            }

            return trimmed + "/" + AcmeChallengeSuffix;
        }

        internal static bool EndsWithChallengeSuffix(string value)
        {
            return value.EndsWith(".well-known/acme-challenge", StringComparison.OrdinalIgnoreCase)
                || value.EndsWith(@".well-known\acme-challenge", StringComparison.OrdinalIgnoreCase);
        }

        internal static int ResolvePort(HttpChallengeDeploymentMethod method, Uri uri, int? explicitPort)
        {
            if (explicitPort is >= 1 and <= 65535)
            {
                return explicitPort.Value;
            }

            if (uri.Port is >= 1 and <= 65535)
            {
                return uri.Port;
            }

            return method switch
            {
                HttpChallengeDeploymentMethod.Ftp => 21,
                HttpChallengeDeploymentMethod.Sftp => 22,
                HttpChallengeDeploymentMethod.WebDav or HttpChallengeDeploymentMethod.Rest =>
                    string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ? 443 : 80,
                _ => 80
            };
        }

        internal static string WithExplicitPort(string url, int? explicitPort)
        {
            if (explicitPort is not (>= 1 and <= 65535))
            {
                return url;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                return url;
            }

            var host = uri.IdnHost;
            if (host.Contains(':'))
            {
                host = "[" + host + "]";
            }

            var user = string.IsNullOrEmpty(uri.UserInfo) ? string.Empty : uri.UserInfo + "@";
            var pathAndQuery = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            return $"{uri.Scheme}://{user}{host}:{explicitPort.Value}{pathAndQuery}{uri.Fragment}";
        }

        internal static string FormatHostPort(string host, int port) => $"{host}:{port}";

        internal static bool ShouldProbe(HttpChallengeDeploymentOptions options)
        {
            if (options.DisablePublicProbe)
            {
                return false;
            }

            return !string.IsNullOrWhiteSpace(options.PublicValidationUrlTemplate);
        }

        internal static IReadOnlyList<string> ListWebDavCollectionUrls(string directoryUrl)
        {
            if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out var uri))
            {
                return Array.Empty<string>();
            }

            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var urls = new List<string>(segments.Length);
            var path = string.Empty;
            foreach (var segment in segments)
            {
                path += "/" + segment;
                var builder = new UriBuilder(uri) { Path = path };
                urls.Add(builder.Uri.AbsoluteUri.TrimEnd('/'));
            }

            return urls;
        }

        internal static string WebDavConflictMessage(string url)
        {
            return $"WebDAV could not create '{url}'. The parent folder is missing, or the path uses the wrong case. WebDAV paths are case-sensitive.";
        }

        internal static void EnsureWebDavMkcolStatus(int statusCode, string url)
        {
            if (statusCode == 409)
            {
                throw new InvalidOperationException(WebDavConflictMessage(url));
            }

            // 200/201/204 created or already present. 405 means the collection already exists.
            if (statusCode is 200 or 201 or 204 or 405)
            {
                return;
            }

            throw new InvalidOperationException(
                $"WebDAV MKCOL for '{url}' failed with HTTP status {statusCode}.");
        }

        /// <summary>
        /// Uploads the challenge file first. Directory creation runs only when that upload fails.
        /// Parent folders that cannot be checked (Synology shared folders report Exists false and
        /// then deny CreateDirectory) are skipped so the retry can still store the file.
        /// </summary>
        internal static void UploadSftpChallenge(
            ISftpFileSession session,
            string remoteDirectory,
            string remoteFilePath,
            byte[] payload,
            Action<string>? log)
        {
            var firstFailure = TryUpload(session, remoteFilePath, payload);
            if (firstFailure is null)
            {
                return;
            }

            log?.Invoke(
                $"[HTTP-01] SFTP upload did not store the challenge file ({firstFailure.Message}). Creating missing folders and trying again.");
            EnsureSftpDirectories(session, remoteDirectory, log);

            var retryFailure = TryUpload(session, remoteFilePath, payload);
            if (retryFailure is not null)
            {
                throw retryFailure;
            }
        }

        internal static void EnsureSftpDirectories(ISftpFileSession session, string fullPath, Action<string>? log)
        {
            if (string.IsNullOrWhiteSpace(fullPath) || fullPath == "/")
            {
                return;
            }

            var segments = fullPath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var current = "/";
            foreach (var segment in segments)
            {
                current = CombinePath(current, segment);
                if (DirectoryAppearsPresent(session, current, log))
                {
                    continue;
                }

                try
                {
                    session.CreateDirectory(current);
                }
                catch (Exception ex) when (IsToleratedSftpDirectoryError(ex))
                {
                    log?.Invoke(
                        $"[HTTP-01] SFTP folder '{current}' was not created ({ex.Message}). Continuing because the folder may already exist.");
                }
            }
        }

        internal static bool IsToleratedSftpDirectoryError(Exception ex)
        {
            if (ex is SftpPermissionDeniedException)
            {
                return true;
            }

            if (ex is SftpException sftp && sftp.StatusCode == StatusCode.PermissionDenied)
            {
                return true;
            }

            var message = ex.Message ?? string.Empty;
            return message.Contains("permission denied", StringComparison.OrdinalIgnoreCase)
                || message.Contains("already exists", StringComparison.OrdinalIgnoreCase);
        }

        internal static async Task RunBestEffortCleanupAsync(Func<Task> cleanup, Action<string>? log, string logPrefix)
        {
            try
            {
                await cleanup().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log?.Invoke($"{logPrefix} Cleanup warning: {ex.Message}");
            }
        }

        private static Exception? TryUpload(ISftpFileSession session, string remoteFilePath, byte[] payload)
        {
            try
            {
                using var stream = new MemoryStream(payload, writable: false);
                session.UploadFile(stream, remoteFilePath, canOverride: true);
                return null;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                return ex;
            }
        }

        private static bool DirectoryAppearsPresent(ISftpFileSession session, string path, Action<string>? log)
        {
            try
            {
                return session.Exists(path);
            }
            catch (Exception ex) when (IsMissingSftpPath(ex))
            {
                return false;
            }
            catch (Exception ex) when (IsToleratedSftpDirectoryError(ex))
            {
                log?.Invoke($"[HTTP-01] Could not check SFTP folder '{path}': {ex.Message}");
                return false;
            }
        }

        internal static bool IsMissingSftpPath(Exception ex)
        {
            if (ex is SftpException sftp && sftp.StatusCode == StatusCode.NoSuchFile)
            {
                return true;
            }

            return (ex.Message ?? string.Empty).Contains("no such file", StringComparison.OrdinalIgnoreCase);
        }

        private static string CombinePath(string directory, string segment)
        {
            var trimmed = directory.TrimEnd('/');
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                return "/" + segment;
            }

            return trimmed + "/" + segment;
        }
    }
}
