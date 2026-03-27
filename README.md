# ACME Certificate Manager

**The friendliest Windows app for free Let's Encrypt certificates**  
Built for Caveman_8080 – no command line, no extra installs, one single .exe!

## ✅ Quick Start (30 seconds)
1. Download the latest .exe from **Releases** (or build it below)
2. Double-click `ACMECertManager.exe`
3. Go to “Issue New Certificate” tab and click the big button

**Always starts in STAGING mode** – safe for testing. Flip the toggle only when ready for real certificates.

## Features
- Dashboard with big friendly buttons
- Issue wizard (domains, wildcards, HTTP-01 auto, DNS-01 ready)
- Manage certificates (list, expiry, renew/revoke)
- Auto-renew via Windows Task Scheduler
- Logs tab with colored output
- All files stay inside the app folder (certs/, certificates.json)
- Self-contained single .exe (runs on any Windows 10/11)

## How to Get Your .exe (2 ways)

**Way 1 – Easiest (GitHub Actions already built it)**
- Go to **Actions** tab → click latest workflow → download “ACMECertManager-exe” artifact

**Way 2 – Build yourself**
1. Install free **Visual Studio 2022 Community**
2. Open `ACMECertManager.sln`
3. Press **F5** to run immediately
4. To create single .exe: right-click project → Publish → self-contained win-x64 → Publish

## Security Tips
- Start in staging mode!
- Run as Administrator first time (for HTTP-01 on port 80)
- Certificates auto-saved in `certs/` folder

**License:** GPL v3  
**Made with ❤️ just for you, Caveman8080!**

Repo: https://github.com/caveman8080/ACMECertManager
