namespace ACMECertManager
{
    public class CertificateModel
    {
        public string Domain { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public string Status { get; set; } = string.Empty;
        public string PfxPath { get; set; } = string.Empty;
        public string OutputDirectory { get; set; } = string.Empty;
        public string CertificatePemPath { get; set; } = string.Empty;
        public string ChainPemPath { get; set; } = string.Empty;
        public string FullChainPemPath { get; set; } = string.Empty;
        public string PrivateKeyPemPath { get; set; } = string.Empty;
        public string AcmeDirectoryUrl { get; set; } = string.Empty;
        public string ValidationMethod { get; set; } = "HTTP-01";

        // Replay settings captured at issue time. Omitted JSON properties keep these defaults.
        public string Email { get; set; } = string.Empty;
        public string KeyAlgorithm { get; set; } = string.Empty;
        public bool? CreatePfxFile { get; set; }
        public string DnsPluginId { get; set; } = string.Empty;

        public string HttpDeploymentMethod { get; set; } = string.Empty;
        public string HttpTarget { get; set; } = string.Empty;
        public string HttpUsername { get; set; } = string.Empty;
        public string HttpPassword { get; set; } = string.Empty;
        public string HttpPublicValidationUrlTemplate { get; set; } = string.Empty;
        public string HttpRestMethod { get; set; } = string.Empty;
        public string HttpAdditionalHeaderName { get; set; } = string.Empty;
        public string HttpAdditionalHeaderValue { get; set; } = string.Empty;
        public string HttpBearerToken { get; set; } = string.Empty;
        public bool HttpSkipTlsCertificateValidation { get; set; }
    }
}
