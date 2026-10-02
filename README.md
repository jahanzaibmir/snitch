# Snitch

Snitch is a secret detection tool that scans GitHub repositories and codebases for accidentally committed API keys, passwords, tokens, and private keys.
It runs 30 plus detection patterns with entropy analysis across every file and every git commit, then gives you a clean report showing exactly where each secret is, how serious it is. Built for developers who want to catch credential leaks before they become a real problem.

---


## What it detects

| Category       | Examples                              |
|----------------|---------------------------------------|
| Cloud          | AWS keys, GCP service accounts, Azure |
| Source Control | GitHub PAT, GitLab tokens             |
| Payment        | Stripe, PayPal, Braintree             |
| Communication  | Twilio, SendGrid, Mailgun, Slack      |
| Auth           | JWT tokens, OAuth client secrets      |
| Database       | PostgreSQL, MySQL, MongoDB URLs       |
| Cryptography   | RSA, EC, SSH, PGP private keys        |
| AI Services    | OpenAI, Anthropic, HuggingFace        |

---


## Severity Levels

| Level    | Meaning                                         |
|----------|-------------------------------------------------|
| CRITICAL | Immediate risk —> rotate/revoke now              |
| HIGH     | Significant exposure —> rotate soon              |
| MEDIUM   | Possible secret — >review and rotate if real     |
| LOW      | Low-confidence match —> manual review needed     |

---

## How it works

1. **Pattern matching** — 30+ regex patterns targeting known secret formats
2. **Entropy analysis** — Shannon entropy filters out placeholder/test values
3. **False positive reduction** — skips `node_modules`, example files, binary files, test fixtures
4. **Git history scan** — walks commit diffs to catch secrets removed from current files
5. **Severity scoring** — entropy + pattern type + context (commented, git history) determines final severity

---

## How to contribute
Contributions are welcome! Fork the repository, create a branch, make your changes, and open a Pull Request.
