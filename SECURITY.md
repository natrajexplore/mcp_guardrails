# Security Policy

## Supported versions
| Version | Supported |
|---|---|
| 1.x | yes |

## Reporting a vulnerability
Please **do not** open a public issue. Use GitHub's private vulnerability reporting
(*Security* tab, then *Report a vulnerability*) or contact the maintainer privately. Include affected version,
impact, and reproduction steps. You will get an acknowledgement within 5 working days and a fix or mitigation plan
within 30 days for confirmed issues.

## Operational guidance
- Run with least privilege: dedicated identities per agent and per approver; tokens stored only as SHA-256 digests.
- Keep credentials in environment variables or a secret manager, never in config files committed to Git.
- Verify TLS (`verify_tls: true`) in production.
