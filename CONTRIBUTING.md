# Contributing to ACMECertManager

Thank you for helping improve ACMECertManager.

This project is a small portable Windows app for everyday personal use. It issues a few Let's Encrypt certificates (for example a NAS, a webcam, or a self-hosted page) and lists the ones it has issued. It is not a business or company product. Certificates are requested with HTTP-01, TLS-ALPN-01, or DNS-01. Renew replays the settings saved when the certificate was issued and asks Let's Encrypt for a new certificate. It does not open the issue form. Older records that do not have those settings only write a log line.

## Project At A Glance

- Main app: src/ (C# WPF on .NET 10, Windows only; published as a portable zip for win-x86, win-x64, and win-arm64)
- Shared library: src/ACMECertManager.Core (ACME and storage code, no WPF)
- Tests: tests/ACMECertManager.Tests (xUnit)
- DNS plugins: published separately at https://github.com/caveman8080/ACMECertManager-DnsPlugins
- Docs: README.md and docs/PLUGIN_DEVELOPMENT.md

## Development Environment

### Requirements

- Windows 10 or Windows 11
- .NET SDK 10.0.x
- Git
- Optional: Visual Studio Code or Visual Studio

### Clone And Restore

```powershell
git clone https://github.com/caveman8080/ACMECertManager.git
cd ACMECertManager
dotnet restore
```

### Build

```powershell
dotnet build ACMECertManager.sln -c Debug
```

### Run The App

```powershell
dotnet run --project src/ACMECertManager.csproj -c Debug
```

Note: HTTP-01 self-hosted validation uses port 80, which must be free, and may require running as Administrator. TLS-ALPN-01 uses port 443, which must be free, and may also ask to run as Administrator.

### Run Tests

```powershell
dotnet test ACMECertManager.sln -c Debug --no-build
```

## Repository Structure

- src/ACMECertManager.Core/AcmeService.cs: ACME protocol, challenge orchestration, issuance logic
- src/MainWindow.xaml and src/MainWindow.xaml.cs: WPF UI flow and user actions
- src/ACMECertManager.Core/CertificateStorage.cs and src/ACMECertManager.Core/CertificateModel.cs: certificate persistence and data model
- src/ACMECertManager.Core/DnsPlugins.cs and src/ACMECertManager.Core/DnsSecretStorage.cs: DNS plugin loading and secrets persistence
- tests/ACMECertManager.Tests: unit tests for storage/model and helper behavior

## Coding Standards

Please follow existing project conventions:

- Keep nullable reference types enabled and preserve null-safety checks.
- Keep async operations async (do not block the UI thread with .Wait() or .Result).
- Keep ACME logic in service-layer files and UI behavior in WPF window code-behind.
- In user-triggered UI handlers, log useful progress and surface blocking errors with MessageBox.
- Preserve compatibility with persisted files in storage/ (for example certificates.json and acme-account.json).
- Prefer focused, minimal changes over broad refactors unless discussed first.

## Testing Expectations

For most PRs:

1. Build the solution in Debug.
2. Run unit tests.
3. Manually verify affected UI flows when relevant.

Manual checks are especially important for:

- Certificate issuance, renewal, and revocation. Renew replays saved issue settings and does not open the issue form.
- HTTP-01 deployment options
- DNS-01 plugin workflows
- Runtime storage behavior (certs/, logs/, storage/, plugins/)

## Reporting Bugs

Use the Bug Report issue template and include:

- Windows version
- .NET SDK version (`dotnet --info`)
- Exact steps to reproduce
- Expected behavior vs actual behavior
- Relevant log excerpts (remove sensitive values)
- Screenshots if UI-related

## Suggesting Features

Use the Feature Request issue template and include:

- Problem statement
- Proposed behavior
- Alternative options considered
- Any ACME, UX, or platform constraints

## Pull Request Process

1. Fork the repository and create a topic branch from main.
2. Keep changes scoped and atomic.
3. Add or update tests when behavior changes.
4. Update docs when user-facing behavior or workflows change.
5. Ensure local build and tests pass.
6. Open a pull request using the PR template.

### PR Checklist

- I built the solution successfully.
- I ran tests and confirmed they pass.
- I added or updated tests for behavior changes.
- I updated docs/README when needed.
- I avoided committing secrets or credentials.

## Security And Secrets

- Do not commit keys, tokens, passwords, or certificate private material.
- If you discover a security issue, do not open a public issue. Follow SECURITY.md instead.

## Questions

If you are unsure about design or scope, open an issue before implementing large changes.

Thanks again for contributing.
