# ACME Certificate Manager

[![CI (.NET 9)](https://github.com/caveman8080/ACMECertManager/actions/workflows/ci.yml/badge.svg)](https://github.com/caveman8080/ACMECertManager/actions/workflows/ci.yml)

**The friendliest Windows app for free Let's Encrypt certificates**  
Built for Caveman_8080 – no command line, no extra installs, one single .exe!

## ✅ Quick Start (30 seconds)
1. Download the latest architecture artifact from **Actions/Releases** (acm-win-x86, acm-win-x64, or acm-win-arm64)
2. Extract the package and run `acm.exe`
3. Go to “Issue New Certificate” tab and click the big button

**Always starts in STAGING mode** – safe for testing. Flip the toggle only when ready for real certificates.

## Requirements
- Minimum runtime for development and source builds: .NET 9 (net9.0-windows).
- Minimum SDK for local build/test/publish commands: .NET SDK 9.0.
- Windows 10/11.

## Features
- Dashboard with big friendly buttons
- Issue wizard (domains, wildcards, HTTP-01 auto, DNS-01 plugin workflow)
- Manage certificates (list, expiry, renew/revoke)
- Logs tab with colored output
- Runtime folders auto-created next to the executable (plugins/, logs/, certs/, storage/)
- Self-contained single .exe (runs on any Windows 10/11)

## Runtime Folder Layout
At startup the app creates these folders beside the executable:
- plugins/ for DNS plugin DLL files
- logs/ for persistent log files
- certs/ for generated certificate files
- storage/ for account/config/secrets JSON files

Legacy root files are migrated to storage/ on startup.

Expected extracted structure:
- ACMECertManager/acm.exe
- ACMECertManager/plugins/
- ACMECertManager/logs/
- ACMECertManager/certs/
- ACMECertManager/storage/

## DNS-01 Plugin Workflow
1. Put provider DLLs in plugins/.
2. Launch the app and open Issue New Certificate.
3. Select DNS-01 and choose a plugin from the dropdown.
4. Fill required plugin fields.
5. Issue certificate.

Operational sequence:
1. Download the pre-built package for your architecture (x86, x64, ARM64).
2. Extract the ACMECertManager directory from the archive.
3. Verify acm.exe, plugins, logs, certs, and storage exist.
4. Place desired DNS plugin DLLs into plugins/.
5. Start the app to auto-scan and load plugin DLLs.
6. Choose DNS-01 and select the plugin from the DNS dropdown.
7. Enter plugin-required credentials and provider data.
8. After issuance, certificate files are saved in certs/ and shown in Manage Certificates.
9. Use Revoke Selected (CA) and Delete Selected (Local) for certificate lifecycle actions.

Warning: DNS plugin secrets are currently stored in plaintext in storage/dns-secrets.json.

Advanced option:
- In Settings, enable Also save PEM artifacts (fullchain, chain, cert, key) alongside PFX to persist both output formats.

## How to Get Your .exe (2 ways)

**Way 1 – Easiest (GitHub Actions already built it)**
- Go to **Actions** tab → click latest workflow → download your architecture artifact (`acm-win-x86`, `acm-win-x64`, `acm-win-arm64`)

**Way 2 – Build yourself**
1. Install free **Visual Studio 2022 Community** with .NET 9 support (or install .NET SDK 9.0).
2. Open `ACMECertManager.sln`
3. Press **F5** to run immediately
4. To create single .exe: right-click project → Publish → self-contained win-x64 → Publish

## Security Tips
- Start in staging mode!
- Run as Administrator first time (for HTTP-01 on port 80)
- Certificates auto-saved in `certs/` folder
- DNS plugin credentials are stored unsecured (plaintext) in `storage/dns-secrets.json`

## Plugin Development
See PLUGIN_DEVELOPMENT.md for instructions on building custom DNS plugin DLLs.

Sample implementation included: samples/HurricaneElectricDnsPlugin

**License:** GPL v3  

Repo: https://github.com/caveman8080/ACMECertManager
