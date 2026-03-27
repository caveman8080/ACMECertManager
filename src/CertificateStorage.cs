using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ACMECertManager
{
    public static class CertificateStorage
    {
        private const string StorageFile = "certificates.json";

        public static List<CertificateModel> Load()
        {
            if (!File.Exists(StorageFile)) return new List<CertificateModel>();
            var json = File.ReadAllText(StorageFile);
            return JsonSerializer.Deserialize<List<CertificateModel>>(json) ?? new();
        }

        public static void Save(List<CertificateModel> certs)
        {
            var json = JsonSerializer.Serialize(certs, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(StorageFile, json);
        }
    }
}
