---
description: "Use when changing ACME issuance, challenge validation, domain ordering, account persistence, or renewal and revocation flows. Covers staging defaults, HttpListener requirements, and certificate storage compatibility."
name: "ACME Flow Guidelines"
applyTo: src/AcmeService.cs, src/MainWindow.xaml.cs, src/CertificateModel.cs, src/CertificateStorage.cs
---
# ACME Flow Guidelines

- Keep certificate issuance defaulted to Lets Encrypt staging unless the user explicitly enables production mode.
- Preserve account persistence behavior with acme-account.json so existing accounts continue to work.
- Preserve certificate output compatibility: cert files in certs/ and metadata stored in certificates.json.
- Maintain HTTP-01 validation behavior on port 80 and preserve clear logging for admin-rights or listener failures.
- Keep network and ACME calls asynchronous to avoid blocking the WPF UI thread.
- When changing certificate model fields, preserve backward compatibility for existing JSON data files.
