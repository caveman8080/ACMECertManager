using Certes;
using Certes.Acme;
using Certes.Pkcs;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace ACMECertManager
{
    public class AcmeService
    {
        private const string AccountFile = "acme-account.json";
        private const string CertsFolder = "certs";

        public async Task<CertificateModel> IssueCertificateAsync(string[] domains, string email, string acmeUrl)
        {
            Directory.CreateDirectory(CertsFolder);

            var acme = new AcmeContext(new Uri(acmeUrl));

            // Account (save once)
            IAccountContext account;
            if (File.Exists(AccountFile))
            {
                account = await acme.NewAccount(File.ReadAllText(AccountFile));
            }
            else
            {
                account = await acme.NewAccount(email, true);
                File.WriteAllText(AccountFile, acme.AccountKey.ToPem());
            }

            var order = await acme.NewOrder(domains);

            // HTTP-01 validation
            foreach (var authz in await order.Authorizations())
            {
                var challenge = await authz.Http();
                using var server = new HttpChallengeServer(challenge.Token, challenge.KeyAuthz);
                server.Start();
                await challenge.Validate();
                server.Stop();
            }

            // Generate cert
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var cert = await order.Generate(new CsrInfo
            {
                CommonName = domains[0]
            }, privateKey);
            var pfxBytes = cert.ToPfx(privateKey).Build(domains[0], null);
            var pfxPath = Path.Combine(CertsFolder, $"{domains[0]}.pfx");
            File.WriteAllBytes(pfxPath, pfxBytes);

            return new CertificateModel
            {
                Domain = string.Join(", ", domains),
                Expires = DateTime.UtcNow.AddDays(90),
                Status = "Valid",
                PfxPath = pfxPath
            };
        }
    }

    // Tiny built-in web server for HTTP-01 (runs only during validation)
    public class HttpChallengeServer : IDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly string _token;
        private readonly string _keyAuth;
        private bool _running;

        public HttpChallengeServer(string token, string keyAuth)
        {
            _token = token;
            _keyAuth = keyAuth;
            _listener.Prefixes.Add("http://+:80/.well-known/acme-challenge/");
        }

        public void Start()
        {
            _running = true;
            _listener.Start();
            Task.Run(async () =>
            {
                while (_running)
                {
                    var ctx = await _listener.GetContextAsync();
                    if (ctx.Request.Url?.LocalPath.Contains(_token) == true)
                    {
                        var buffer = System.Text.Encoding.UTF8.GetBytes(_keyAuth);
                        ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
                        ctx.Response.Close();
                    }
                }
            });
        }

        public void Stop() => Dispose();
        public void Dispose()
        {
            _running = false;
            _listener.Stop();
        }
    }
}
