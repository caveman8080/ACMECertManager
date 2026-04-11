# Security Policy

## Supported Versions

Security fixes are provided for the current main branch and the latest published release line.

Older versions may not receive patches.

## Reporting A Vulnerability

Please report security vulnerabilities privately.

Preferred method:

1. Open a private GitHub Security Advisory draft:
   https://github.com/caveman8080/ACMECertManager/security/advisories/new
2. Include details needed to reproduce and assess impact:
   - Affected version/commit
   - Reproduction steps
   - Impact and potential exploitability
   - Suggested mitigation (if known)

Alternative maintainer contact:

- https://github.com/caveman8080

Please do not open public issues for vulnerabilities.

## What To Expect

- Initial acknowledgement target: within 5 business days
- Triage and severity assessment: as soon as practical
- Fix timeline: depends on severity, complexity, and release scheduling
- Coordinated disclosure: we will work with reporters on timing and credit preferences

## Scope Notes For This Project

This application handles certificate workflows, local storage, and optional plugin-based DNS credentials. Relevant security findings may include:

- ACME issuance/challenge validation flaws
- Unsafe handling of certificate/private key files
- Credential exposure risks (including plugin secrets)
- Insecure network transport or validation behavior

## Safe Harbor

If you make a good-faith effort to follow this policy and avoid user harm, we will treat your research as authorized.
