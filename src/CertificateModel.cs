namespace ACMECertManager
{
    public class CertificateModel
    {
        public string Domain { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public string Status { get; set; } = string.Empty;
        public string PfxPath { get; set; } = string.Empty;
        public string AcmeDirectoryUrl { get; set; } = string.Empty;
        public string ValidationMethod { get; set; } = "HTTP-01";
    }
}
