using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace ACMECertManager
{
    /// <summary>
    /// Arguments for <see cref="AcmeService.IssueCertificateAsync"/> except the live DNS plugin execution and log callback.
    /// </summary>
    public sealed class CertificateIssueRequest
    {
        public required string[] Domains { get; init; }
        public required string Email { get; init; }
        public required string AcmeDirectoryUrl { get; init; }
        public required ChallengeValidationMethod ValidationMethod { get; init; }
        public HttpChallengeDeploymentOptions? HttpDeployment { get; init; }
        public string DnsPluginId { get; init; } = string.Empty;
        public required bool CreatePfxFile { get; init; }
        public required CertificateKeyAlgorithm KeyAlgorithm { get; init; }
    }

    /// <summary>
    /// Builds an issuance request from a stored certificate. Does not contact the network and does not guess missing settings.
    /// </summary>
    public static class CertificateRenewalReplay
    {
        public static bool TryCreate(
            CertificateModel model,
            [NotNullWhen(true)] out CertificateIssueRequest? request,
            out IReadOnlyList<string> missing)
        {
            request = null;

            if (model is null)
            {
                missing = new[] { "certificate" };
                return false;
            }

            var gaps = new List<string>();
            var domains = SplitDomains(model.Domain);
            if (domains.Length == 0)
            {
                gaps.Add("domains");
            }

            var email = model.Email?.Trim() ?? string.Empty;
            if (email.Length == 0)
            {
                gaps.Add("email");
            }

            var acmeDirectoryUrl = model.AcmeDirectoryUrl?.Trim() ?? string.Empty;
            if (acmeDirectoryUrl.Length == 0)
            {
                gaps.Add("ACME directory URL");
            }

            var hasValidationMethod = TryParseValidationMethod(model.ValidationMethod, out var validationMethod);
            if (!hasValidationMethod)
            {
                gaps.Add("validation method");
            }

            var hasKeyAlgorithm = TryParseKeyAlgorithm(model.KeyAlgorithm, out var keyAlgorithm);
            if (!hasKeyAlgorithm)
            {
                gaps.Add("key algorithm");
            }

            if (model.CreatePfxFile is null)
            {
                gaps.Add("PFX choice");
            }

            var dnsPluginId = model.DnsPluginId?.Trim() ?? string.Empty;
            if (hasValidationMethod &&
                validationMethod == ChallengeValidationMethod.Dns01 &&
                dnsPluginId.Length == 0)
            {
                gaps.Add("DNS plugin");
            }

            var httpDeploymentMethod = model.HttpDeploymentMethod?.Trim() ?? string.Empty;
            if (hasValidationMethod &&
                validationMethod == ChallengeValidationMethod.Http01 &&
                httpDeploymentMethod.Length == 0)
            {
                gaps.Add("HTTP deployment");
            }

            if (gaps.Count > 0)
            {
                missing = gaps;
                return false;
            }

            HttpChallengeDeploymentOptions? httpDeployment = null;
            if (validationMethod == ChallengeValidationMethod.Http01)
            {
                httpDeployment = BuildHttpDeployment(model, httpDeploymentMethod);
            }

            request = new CertificateIssueRequest
            {
                Domains = domains,
                Email = email,
                AcmeDirectoryUrl = acmeDirectoryUrl,
                ValidationMethod = validationMethod,
                HttpDeployment = httpDeployment,
                DnsPluginId = validationMethod == ChallengeValidationMethod.Dns01 ? dnsPluginId : string.Empty,
                CreatePfxFile = model.CreatePfxFile!.Value,
                KeyAlgorithm = keyAlgorithm
            };
            missing = Array.Empty<string>();
            return true;
        }

        private static string[] SplitDomains(string? domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                return Array.Empty<string>();
            }

            var parts = domain.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
            {
                return Array.Empty<string>();
            }

            var domains = new List<string>(parts.Length);
            foreach (var part in parts)
            {
                if (!string.IsNullOrWhiteSpace(part))
                {
                    domains.Add(part);
                }
            }

            return domains.ToArray();
        }

        private static bool TryParseValidationMethod(string? raw, out ChallengeValidationMethod method)
        {
            method = default;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            var trimmed = raw.Trim();
            if (trimmed.Equals("HTTP-01", StringComparison.OrdinalIgnoreCase))
            {
                method = ChallengeValidationMethod.Http01;
                return true;
            }

            if (trimmed.Equals("TLS-ALPN-01", StringComparison.OrdinalIgnoreCase))
            {
                method = ChallengeValidationMethod.TlsAlpn01;
                return true;
            }

            if (trimmed.Equals("DNS-01", StringComparison.OrdinalIgnoreCase))
            {
                method = ChallengeValidationMethod.Dns01;
                return true;
            }

            return false;
        }

        private static bool TryParseKeyAlgorithm(string? raw, out CertificateKeyAlgorithm algorithm)
        {
            algorithm = default;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            var trimmed = raw.Trim();
            foreach (var name in Enum.GetNames<CertificateKeyAlgorithm>())
            {
                if (!name.Equals(trimmed, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return Enum.TryParse(name, ignoreCase: false, out algorithm) && Enum.IsDefined(algorithm);
            }

            return false;
        }

        private static HttpChallengeDeploymentOptions BuildHttpDeployment(CertificateModel model, string httpDeploymentMethod)
        {
            return new HttpChallengeDeploymentOptions
            {
                Method = AcmeService.ParseHttpDeploymentMethod(httpDeploymentMethod),
                Target = model.HttpTarget ?? string.Empty,
                Username = model.HttpUsername ?? string.Empty,
                Password = model.HttpPassword ?? string.Empty,
                PublicValidationUrlTemplate = model.HttpPublicValidationUrlTemplate ?? string.Empty,
                RestMethod = model.HttpRestMethod ?? string.Empty,
                AdditionalHeaderName = model.HttpAdditionalHeaderName ?? string.Empty,
                AdditionalHeaderValue = model.HttpAdditionalHeaderValue ?? string.Empty,
                BearerToken = model.HttpBearerToken ?? string.Empty,
                SkipTlsCertificateValidation = model.HttpSkipTlsCertificateValidation
            };
        }
    }
}
