using Certes;
using Certes.Acme;
using System;
using System.Threading.Tasks;

namespace ACMECertManager
{
    public class AcmeService
    {
        public async Task<CertificateModel> IssueCertificateAsync(string[] domains, string email, string acmeUrl)
        {
            var acme = new AcmeContext(acmeUrl);
            var account = await acme.NewAccount(email, true);
            var order = await acme.NewOrder(domains);

            var authz = (await order.Authorizations()).First();
            var challenge = await authz.Http();
            // In real app we would start HTTP server for challenge – simplified here for Step 2
            await challenge.Validate();

            var cert = await order.Generate(new CsrBuilder { CommonName = domains[0] });
            var pfx = cert.ToPfx();

            return new CertificateModel
            {
                Domain = string.Join(", ", domains),
                Expires = DateTime.UtcNow.AddDays(90),
                Status = "Issued"
            };
        }
    }
}
