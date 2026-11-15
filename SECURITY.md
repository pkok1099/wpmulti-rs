# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `wpmulti` (such as memory safety issues, authentication bypasses, DNS leaks, or denial-of-service vectors), **please do not open a public GitHub issue**.

Instead, please report it privately using **GitHub Security Advisories** (*Security* -> *Report a vulnerability* in this repository) or contact the repository maintainers directly.

Please include:
- A clear description of the vulnerability and its potential impact.
- Steps or a minimal configuration/reproduction to trigger the issue.
- The version or commit hash of `wpmulti` tested.

## Security Recommendations

- **Admin API**: Keep `admin.listen` bound to `127.0.0.1` or an isolated management interface; do not expose the Admin REST API directly to untrusted public networks.
- **WireGuard Configs**: Never commit `.conf` files containing real private keys or `wpmulti.toml` credentials to version control.
