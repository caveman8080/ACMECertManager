# Project Guidelines

## Code Style
- Keep C# nullable reference types enabled and preserve existing null guards for user input and persisted data.
- Follow current project patterns: block-scoped namespaces, explicit using directives, and async/await for long-running operations.
- In UI event handlers, keep user-facing feedback consistent: write to the log panel and surface blocking failures with MessageBox.

## Architecture
- This repository is a single Windows WPF desktop app targeting net10.0-windows.
- Keep ACME protocol and challenge orchestration in src/AcmeService.cs.
- Keep UI flow and user actions in src/MainWindow.xaml and src/MainWindow.xaml.cs.
- Keep local persistence concerns in src/CertificateStorage.cs and theme persistence in src/App.xaml.cs.
- Keep certificate data model changes in src/CertificateModel.cs and ensure JSON compatibility with existing files.

## Build And Test
- Minimum runtime/SDK for local and CI builds: .NET 10 (net10.0-windows / SDK 10.0.x).
- Restore dependencies: dotnet restore
- Build from repository root: dotnet build src/ACMECertManager.csproj -c Debug
- CI build parity check: dotnet build --no-restore
- Publish single-file executable: dotnet publish src/ACMECertManager.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=false -o publish
- There is currently no automated test project in this repository. Validate changes with a successful build and targeted manual verification in the app UI.

## Conventions
- Default certificate issuance to Let's Encrypt staging unless the user explicitly enables production.
- ACME HTTP-01 validation uses an HttpListener on port 80; changes in that path must preserve admin-rights requirements and clear failure logging.
- App data is intentionally stored next to the executable (certs/, certificates.json, ui-settings.json, acme-account.json). Do not move these paths without a migration plan.
- Preserve self-contained Windows publishing behavior in src/ACMECertManager.csproj unless a change explicitly targets packaging strategy.

## References
- User-facing product behavior and quick-start details are documented in README.md.
- CI packaging workflow is in .github/workflows/ci.yml.