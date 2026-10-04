using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace ACMECertManager
{
    public static class CertificateStorage
    {
        public static List<CertificateModel> Load()
        {
            RuntimePaths.EnsureRequiredDirectories();

            if (!File.Exists(RuntimePaths.CertificatesFile)) return new List<CertificateModel>();
            var json = File.ReadAllText(RuntimePaths.CertificatesFile);
            try
            {
                return JsonSerializer.Deserialize<List<CertificateModel>>(json) ?? new();
            }
            catch (JsonException)
            {
                return new List<CertificateModel>();
            }
        }

        public static void Save(List<CertificateModel> certs)
        {
            RuntimePaths.EnsureRequiredDirectories();

            var json = JsonSerializer.Serialize(certs, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(RuntimePaths.CertificatesFile, json);
        }
    }
}
