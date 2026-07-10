---
description: "Use when changing ACME issuance, challenge validation, domain ordering, account persistence, or renewal and revocation flows. Covers production default, environment-specific account files, CancellationToken support, HttpListener requirements, and certificate storage compatibility."
name: "ACME Flow Guidelines"
applyTo: src/AcmeService.cs, src/MainWindow.xaml.cs, src/CertificateModel.cs, src/CertificateStorage.cs
---
# ACME Flow Guidelines

- Keep certificate issuance **defaulted to Let's Encrypt production** (real certificates). The UI, startup log, and advanced options should reflect production as the default. Use the staging toggle or advanced options in the "Issue New Certificate" tab only when testing.
- The application now automatically manages **environment-specific ACME account files** (`acme-account-production.pem` and `acme-account-staging.pem` in the `storage/` folder). This prevents account and key conflicts when users switch between staging and production environments. Legacy single-file accounts (`acme-account.json`) are automatically migrated to the production account file on startup.
- **CancellationToken support**: `IssueCertificateAsync` (and internal methods like polling, DNS plugin calls, HTTP deployment, and waits) now accept and respect a `CancellationToken`. Long-running operations (DNS propagation delays, ACME polling, network calls) can be cancelled. Call sites should pass a token from a `CancellationTokenSource` when a Cancel button is available. Cleanup paths gracefully handle `OperationCanceledException`.
- Preserve certificate output compatibility: cert files in `certs/` and metadata stored in `certificates.json`.
- Maintain HTTP-01 validation behavior on port 80; if port 80 is in use or access is denied, catch `HttpListenerException` and log actionable guidance for the user, including the detailed exception message and stack trace, through the project's established logging framework.
- Keep network and ACME calls asynchronous to avoid blocking the WPF UI thread.
- When changing certificate model fields, make new fields nullable and assign safe default values during deserialization to preserve backward compatibility for existing JSON data files.
