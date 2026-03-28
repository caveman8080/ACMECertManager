# Hurricane Electric DNS Plugin Sample

This sample plugin implements ACMECertManager DNS-01 hooks for Hurricane Electric DDNS using the same high-level flow as `acme.sh` `dns_he_ddns.sh`:
- Update TXT through `https://dyn.dns.he.net/nic/update`
- Send `hostname`, `password` (DDNS key), and `txt`
- Treat `good` and `nochg` responses as success
- Cleanup is a no-op because HE DDNS updates the same record target

## Build
```powershell
dotnet build samples/HurricaneElectricDnsPlugin/HurricaneElectricDnsPlugin.csproj -c Release
```

## Install into ACMECertManager
1. Build the plugin project.
2. Copy `HurricaneElectricDnsPlugin.dll` into the app `plugins/` folder beside `acm.exe`.
3. Launch ACMECertManager.
4. Select `DNS-01 (plugin)` and choose `Hurricane Electric - DDNS`.
5. Provide credentials:
   - `ddnsKey` (HE DDNS key)
   - `propagationSeconds` (optional wait before ACME validation; default 30)

## Notes
- Credentials are stored by host app in plaintext (`storage/dns-secrets.json`).
- This plugin targets HE DDNS, not the dns.he.net zone-edit form API.
