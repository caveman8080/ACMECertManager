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
    }
}
