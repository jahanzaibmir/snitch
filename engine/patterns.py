"""
Snitch — Secret Detection Patterns
Each pattern has: name, regex, severity, confidence_boost (if entropy is high), remediation
"""

import re

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"

PATTERNS = [
    # ─── Cloud Providers ───────────────────────────────────────────────────────

    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "regex": re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "remediation": "Revoke this key immediately in AWS IAM console. Rotate and store in AWS Secrets Manager or as an environment variable.",
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "regex": re.compile(r'(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|AWS_SECRET_ACCESS_KEY)[_\-\s]?[=:"\s\']+([A-Za-z0-9/+=]{20,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "remediation": "Revoke immediately in AWS IAM. Never hardcode; use IAM roles or environment variables.",
    },
    {
        "id": "gcp_service_account",
        "name": "GCP Service Account Key",
        "regex": re.compile(r'"type"\s*:\s*"service_account"'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "remediation": "Rotate this key in GCP Console. Use Workload Identity Federation instead of service account keys.",
    },
    {
        "id": "azure_storage_key",
        "name": "Azure Storage Account Key",
        "regex": re.compile(r'(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "remediation": "Regenerate the key in Azure Portal. Use Managed Identity or Azure Key Vault.",
    },

    # ─── Source Control & CI/CD ────────────────────────────────────────────────

    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(ghp_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "remediation": "Revoke in GitHub → Settings → Developer Settings → Personal access tokens. Use GitHub Secrets for CI/CD.",
    },
    {
        "id": "github_oauth",
        "name": "GitHub OAuth Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(gho_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "remediation": "Revoke in GitHub OAuth Apps settings. Regenerate and store securely.",
    },
    {
        "id": "github_app_token",
        "name": "GitHub App Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Source Control",
        "remediation": "Revoke and regenerate in GitHub App settings.",
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(glpat-[A-Za-z0-9\-_]{20})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "remediation": "Revoke in GitLab → User Settings → Access Tokens.",
    },

    # ─── Payment Processors ────────────────────────────────────────────────────

    {
        "id": "stripe_secret_key",
        "name": "Stripe Secret Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "remediation": "Roll the key immediately in Stripe Dashboard → Developers → API keys.",
    },
    {
        "id": "stripe_restricted_key",
        "name": "Stripe Restricted Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(rk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Payment",
        "remediation": "Roll the key in Stripe Dashboard. Store in environment variable.",
    },
    {
        "id": "paypal_secret",
        "name": "PayPal / Braintree Secret",
        "regex": re.compile(r'(?i)(?:paypal|braintree)[_\-\s]?(?:secret|client_secret|access_token)[_\-\s]?[=:"\s]+([A-Za-z0-9_\-]{16,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "remediation": "Revoke in PayPal Developer Dashboard. Rotate credentials.",
    },

    # ─── Communication APIs ────────────────────────────────────────────────────

    {
        "id": "twilio_account_sid",
        "name": "Twilio Account SID",
        "regex": re.compile(r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Rotate auth token in Twilio Console. Store credentials in environment variables.",
    },
    {
        "id": "twilio_auth_token",
        "name": "Twilio Auth Token",
        "regex": re.compile(r'(?i)twilio[_\-\s]?auth[_\-\s]?token[_\-\s]?[=:"\s]+([a-f0-9]{32})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Communication",
        "remediation": "Rotate immediately in Twilio Console.",
    },
    {
        "id": "sendgrid_api_key",
        "name": "SendGrid API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9.])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9.])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Revoke in SendGrid → Settings → API Keys. Create a new restricted key.",
    },
    {
        "id": "mailgun_api_key",
        "name": "Mailgun API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(key-[a-f0-9]{32})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Regenerate in Mailgun → Account → Security.",
    },

    # ─── Auth & Identity ───────────────────────────────────────────────────────

    {
        "id": "jwt_token",
        "name": "JSON Web Token",
        "regex": re.compile(r'(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)(?![A-Za-z0-9_\-])'),
        "severity": SEVERITY_HIGH,
        "category": "Auth",
        "remediation": "Invalidate this token immediately. Never hardcode JWTs; they should be issued dynamically.",
    },
    {
        "id": "oauth_client_secret",
        "name": "OAuth Client Secret",
        "regex": re.compile(r'(?i)client[_\-]?secret[_\-\s]?[=:"\s]+([A-Za-z0-9_\-]{16,64})'),
        "severity": SEVERITY_HIGH,
        "category": "Auth",
        "remediation": "Rotate in your OAuth provider. Store in environment variables or a secrets manager.",
    },

    # ─── Database Credentials ──────────────────────────────────────────────────

    {
        "id": "db_connection_string",
        "name": "Database Connection String",
        "regex": re.compile(r'(?i)((?:mysql|postgresql|postgres|mongodb|redis|mssql|oracle|sqlite|mariadb):\/\/[^:]+:[^@\s"\']+@[^\s"\']+)'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "remediation": "Rotate database credentials immediately. Use environment variables or a secrets manager like Vault.",
    },
    {
        "id": "generic_password",
        "name": "Hardcoded Password",
        "regex": re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\'"]'),
        "severity": SEVERITY_MEDIUM,
        "category": "Database",
        "remediation": "Remove hardcoded password. Use environment variables: os.environ.get('DB_PASSWORD')",
    },

    # ─── Private Keys ──────────────────────────────────────────────────────────

    {
        "id": "rsa_private_key",
        "name": "RSA Private Key",
        "regex": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "remediation": "Revoke and regenerate this key pair immediately. Never commit private keys to version control.",
    },
    {
        "id": "ec_private_key",
        "name": "EC Private Key",
        "regex": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "remediation": "Revoke and regenerate. Store private keys in a hardware security module or secrets manager.",
    },
    {
        "id": "openssh_private_key",
        "name": "OpenSSH Private Key",
        "regex": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "remediation": "Revoke this SSH key from all authorized_keys files. Generate a new key pair.",
    },
    {
        "id": "pgp_private_key",
        "name": "PGP Private Key Block",
        "regex": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "remediation": "Revoke this PGP key and generate a new one. Notify any parties that trusted it.",
    },

    # ─── Generic High-Entropy Patterns ────────────────────────────────────────

    {
        "id": "generic_api_key",
        "name": "Generic API Key",
        "regex": re.compile(r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?secret|secret[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\'"]?'),
        "severity": SEVERITY_MEDIUM,
        "category": "Generic",
        "remediation": "Identify the service this key belongs to and rotate it. Move to environment variable.",
    },
    {
        "id": "generic_token",
        "name": "Generic Token",
        "regex": re.compile(r'(?i)(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\'"]?'),
        "severity": SEVERITY_MEDIUM,
        "category": "Generic",
        "remediation": "Rotate this token with the issuing service. Store in environment variables.",
    },

    # ─── Social / Developer APIs ───────────────────────────────────────────────

    {
        "id": "slack_webhook",
        "name": "Slack Webhook URL",
        "regex": re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Revoke in Slack → App → Incoming Webhooks. Generate a new webhook URL.",
    },
    {
        "id": "slack_token",
        "name": "Slack API Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(xox[baprs]-[A-Za-z0-9\-]+)(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Revoke in Slack API dashboard. Rotate and store as environment variable.",
    },
    {
        "id": "discord_token",
        "name": "Discord Bot Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])([MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Regenerate in Discord Developer Portal → Bot → Reset Token.",
    },
    {
        "id": "telegram_bot_token",
        "name": "Telegram Bot Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(\d{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "remediation": "Revoke via BotFather (/revoke). Generate a new token.",
    },

    # ─── AI / ML Services ─────────────────────────────────────────────────────

    {
        "id": "openai_api_key",
        "name": "OpenAI API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk-[A-Za-z0-9]{48})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "AI Services",
        "remediation": "Revoke in OpenAI Platform → API Keys. This can incur serious financial cost if abused.",
    },
    {
        "id": "anthropic_api_key",
        "name": "Anthropic API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk-ant-[A-Za-z0-9\-_]{40,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "AI Services",
        "remediation": "Revoke in Anthropic Console → API Keys immediately.",
    },
    {
        "id": "huggingface_token",
        "name": "HuggingFace Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(hf_[A-Za-z0-9]{34,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "AI Services",
        "remediation": "Revoke in HuggingFace → Settings → Access Tokens.",
    },
]

# ─── False Positive Filters ────────────────────────────────────────────────────
# Patterns that indicate a value is likely a placeholder, not a real secret

PLACEHOLDER_PATTERNS = [
    re.compile(r'(?i)(example|sample|test|fake|dummy|placeholder|your[_\-]?|<[^>]+>|\$\{[^}]+\}|%[A-Z_]+%|xxx+|0{8,}|1{8,})'),
    re.compile(r'(?i)(insert[_\-]?here|replace[_\-]?me|change[_\-]?me|todo|fixme|none|null|undefined|empty|default)'),
]

# File extensions to skip entirely
SKIP_EXTENSIONS = {
    '.md', '.rst', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.pdf', '.zip', '.tar', '.gz', '.lock', '.sum',
    '.min.js',  # minified files — too much noise
}

# File/directory names to skip
SKIP_PATHS = {
    'node_modules', '.git', '__pycache__', 'dist', 'build',
    'vendor', '.venv', 'venv', 'env', '.env.example',
    'test_fixtures', 'fixtures', 'mocks', '__mocks__',
}

# Files that are almost always test/example files
SKIP_FILENAMES = {
    '.env.example', '.env.sample', '.env.test', 'example.env',
    'secrets.example.yaml', 'config.example.json',
}
