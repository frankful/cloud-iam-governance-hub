# Security Policy

## Reporting a Vulnerability

Please report security issues privately to:

- Email: tangdou.xuan@gmail.com

Do not open a public issue for security reports. Include:

- Affected version or commit
- Affected component (API, workers, frontend, migrations, publisher)
- Reproduction steps or proof of concept
- Potential impact

We aim to acknowledge reports within 3 business days and provide a fix or
mitigation plan as soon as practical.

## Scope

The following are in scope:

- Authentication and RBAC bypass
- Authorization boundary between standard users and platform admins
- Terraform generation that could destroy or escalate IAM permissions
- Publisher token handling or credential leakage
- SQL injection, SSRF, or unsafe URL handling
- Audit tampering or evidence forgery

The following are explicitly out of scope:

- AWS account root credentials or IAM user credentials stored by the platform
  (the platform does not create or store these)
- Vulnerabilities in third-party dependencies without a platform-specific
  impact
- Compliance certification, QSA opinions, or ASV scans

## Supported Versions

Only the latest release is supported for security fixes. Please report against
the newest tag or `main`.
