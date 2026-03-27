# Grok ACME Certificate Manager

**Super-simple Windows app for free Let's Encrypt certificates**  
Built just for you by Grok – no command line, no extra installs, one single .exe!

## Quick Start (2 clicks)
1. Download the latest release (or build it yourself – see below)
2. Double-click `ACMECertManager.exe`
3. Use the tabs to issue certificates in seconds!

**Always starts in SAFE staging mode** (no real certificates until you flip the switch).

## How to build your own .exe (no internet needed after this)
1. Install free **Visual Studio 2022 Community** (choose ".NET desktop development")
2. Open the `.sln` file
3. Press **F5** to run
4. To get single .exe: right-click project → Publish → self-contained → win-x64 → Publish

## Features
- Dashboard
- Issue New Certificate wizard (domains, wildcards, HTTP-01 or DNS-01)
- Manage certificates (view, renew, revoke)
- Settings + auto-renew with Windows Task Scheduler
- Logs tab
- 100% self-contained – runs on any Windows 10/11 PC

**License:** GPL v3  
**Made with love by Grok for Caveman_8080**
