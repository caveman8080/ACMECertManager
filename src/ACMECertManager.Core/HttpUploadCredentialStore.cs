using System;
using System.Collections.Generic;
using System.Linq;

namespace ACMECertManager
{
    /// <summary>
    /// HTTP-01 upload settings stored on a certificate so renewal can reuse them.
    /// </summary>
    public sealed class HttpUploadCredentialRecord
    {
        public string Domain { get; init; } = string.Empty;
        public string OutputDirectory { get; init; } = string.Empty;
        public string DeploymentMethod { get; init; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public int? Port { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string BearerToken { get; set; } = string.Empty;
        public string AdditionalHeaderValue { get; set; } = string.Empty;
    }

    /// <summary>
    /// Reads and updates per-certificate HTTP upload credentials in the certificate list.
    /// Passwords and bearer tokens are stored unchanged, including surrounding spaces.
    /// </summary>
    public static class HttpUploadCredentialStore
    {
        public static bool HasEditableCredentials(CertificateModel model)
        {
            if (model is null)
            {
                return false;
            }

            var method = model.HttpDeploymentMethod?.Trim() ?? string.Empty;
            if (method.Length == 0 ||
                method.Equals(HttpChallengeDeploymentMethod.SelfHosted.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        public static List<HttpUploadCredentialRecord> List(IEnumerable<CertificateModel> certificates)
        {
            var records = new List<HttpUploadCredentialRecord>();
            if (certificates is null)
            {
                return records;
            }

            foreach (var model in certificates)
            {
                if (!HasEditableCredentials(model))
                {
                    continue;
                }

                records.Add(ToRecord(model));
            }

            return records;
        }

        public static bool TryApply(IList<CertificateModel> certificates, HttpUploadCredentialRecord edit, out string error)
        {
            error = string.Empty;
            if (certificates is null || edit is null)
            {
                error = "Certificate list is missing.";
                return false;
            }

            var match = certificates.FirstOrDefault(model => IsSameCertificate(model, edit));
            if (match is null)
            {
                error = "That certificate is no longer in certificates.json.";
                return false;
            }

            if (edit.Port is < 1 or > 65535)
            {
                error = "Port must be a whole number from 1 to 65535, or left blank.";
                return false;
            }

            var method = AcmeService.ParseHttpDeploymentMethod(match.HttpDeploymentMethod);
            match.HttpTarget = HttpDeploymentSupport.NormalizeChallengeTarget(method, edit.Target);
            match.HttpPort = edit.Port;
            match.HttpUsername = edit.Username?.Trim() ?? string.Empty;
            match.HttpPassword = edit.Password ?? string.Empty;
            match.HttpBearerToken = edit.BearerToken ?? string.Empty;
            match.HttpAdditionalHeaderValue = edit.AdditionalHeaderValue ?? string.Empty;
            return true;
        }

        public static string Mask(string? value, bool revealed)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return revealed ? value : "••••••";
        }

        private static HttpUploadCredentialRecord ToRecord(CertificateModel model)
        {
            return new HttpUploadCredentialRecord
            {
                Domain = model.Domain ?? string.Empty,
                OutputDirectory = model.OutputDirectory ?? string.Empty,
                DeploymentMethod = model.HttpDeploymentMethod ?? string.Empty,
                Target = model.HttpTarget ?? string.Empty,
                Port = model.HttpPort,
                Username = model.HttpUsername ?? string.Empty,
                Password = model.HttpPassword ?? string.Empty,
                BearerToken = model.HttpBearerToken ?? string.Empty,
                AdditionalHeaderValue = model.HttpAdditionalHeaderValue ?? string.Empty
            };
        }

        private static bool IsSameCertificate(CertificateModel model, HttpUploadCredentialRecord edit)
        {
            if (!string.IsNullOrWhiteSpace(edit.OutputDirectory) || !string.IsNullOrWhiteSpace(model.OutputDirectory))
            {
                return string.Equals(model.OutputDirectory ?? string.Empty, edit.OutputDirectory, StringComparison.OrdinalIgnoreCase);
            }

            return string.Equals(model.Domain ?? string.Empty, edit.Domain, StringComparison.OrdinalIgnoreCase)
                && string.Equals(model.HttpDeploymentMethod ?? string.Empty, edit.DeploymentMethod, StringComparison.OrdinalIgnoreCase);
        }
    }
}
