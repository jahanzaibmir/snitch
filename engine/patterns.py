"""

snitch engine/patterns.py"""


import re

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"




PATTERNS = [



PATTERNS = [



    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "regex": re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Revoke immediately in AWS IAM console. Rotate and store via AWS Secrets Manager or environment variable.",
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "regex": re.compile(r'(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:"\s\']+([A-Za-z0-9/+=]{40})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Revoke immediately in AWS IAM. Use IAM roles or environment variables — never hardcode.",
    },
    {
        "id": "aws_mws_key",
        "name": "AWS Marketplace Web Service Key",
        "regex": re.compile(r'(?<![A-Z0-9])(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Revoke in AWS Seller Central. Rotate and store as environment variable.",
    },
    {
        "id": "aws_session_token",
        "name": "AWS Session Token",
        "regex": re.compile(r'(?i)aws[_\-\s]?session[_\-\s]?token\s*[=:"\s\']+([A-Za-z0-9/+=]{100,})'),
        "severity": SEVERITY_HIGH,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Session tokens expire, but check if the underlying credentials are compromised.",
    },


    {
        "id": "gcp_service_account",
        "name": "GCP Service Account Key",
        "regex": re.compile(r'"type"\s*:\s*"service_account"'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Rotate in GCP Console immediately. Use Workload Identity Federation instead of service account keys.",
    },
    {
        "id": "gcp_api_key",
        "name": "GCP API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Restrict and rotate in GCP Console → APIs & Services → Credentials.",
    },
    {
        "id": "gcp_oauth",
        "name": "GCP OAuth Client ID",
        "regex": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "severity": SEVERITY_MEDIUM,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "OAuth client IDs are semi-public but rotate the associated secret in GCP Console.",
    },
    {
        "id": "firebase_api_key",
        "name": "Firebase API Key",
        "regex": re.compile(r'(?i)firebase[_\-\s]?(?:api[_\-\s]?)?key\s*[=:"\s\']+([A-Za-z0-9_\-]{35,45})'),
        "severity": SEVERITY_HIGH,
        "category": "Cloud",
        "confidence": "medium",
        "remediation": "Restrict and rotate in Firebase Console → Project Settings → API keys.",
    },
    {
        "id": "firebase_url",
        "name": "Firebase Database URL",
        "regex": re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
        "severity": SEVERITY_MEDIUM,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Check Firebase security rules. If open, lock down immediately in Firebase Console.",
    },


    {
        "id": "azure_storage_key",
        "name": "Azure Storage Account Key",
        "regex": re.compile(r'(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{86,90})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "high",
        "remediation": "Regenerate in Azure Portal. Use Managed Identity or Azure Key Vault.",
    },
    {
        "id": "azure_client_secret",
        "name": "Azure Client Secret",
        "regex": re.compile(r'(?i)(?:azure|az)[_\-\s]?client[_\-\s]?secret\s*[=:"\s\']+([A-Za-z0-9~._\-]{30,50})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cloud",
        "confidence": "medium",
        "remediation": "Rotate in Azure Active Directory → App registrations → Certificates & Secrets.",
    },
    {
        "id": "azure_sas_token",
        "name": "Azure SAS Token",
        "regex": re.compile(r'(?i)(?:sig=)([A-Za-z0-9%+/]{40,})(?:&|$|\s)'),
        "severity": SEVERITY_HIGH,
        "category": "Cloud",
        "confidence": "medium",
        "remediation": "Revoke the SAS token in Azure Portal and generate a new one with minimal permissions.",
    },


    {
        "id": "github_pat",
        "name": "GitHub Personal Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(ghp_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "confidence": "high",
        "remediation": "Revoke in GitHub → Settings → Developer Settings → Personal access tokens. Use GitHub Actions secrets instead.",
    },
    {
        "id": "github_oauth",
        "name": "GitHub OAuth Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(gho_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "confidence": "high",
        "remediation": "Revoke in GitHub OAuth Apps settings and regenerate.",
    },
    {
        "id": "github_app_token",
        "name": "GitHub App Installation Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(ghs_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Source Control",
        "confidence": "high",
        "remediation": "Revoke and regenerate in GitHub App settings.",
    },
    {
        "id": "github_fine_grained_pat",
        "name": "GitHub Fine-Grained PAT",
        "regex": re.compile(r'(?<![A-Za-z0-9])(github_pat_[A-Za-z0-9_]{82})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "confidence": "high",
        "remediation": "Revoke in GitHub → Settings → Developer Settings → Fine-grained tokens.",
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(glpat-[A-Za-z0-9\-_]{20})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "confidence": "high",
        "remediation": "Revoke in GitLab → User Settings → Access Tokens.",
    },
    {
        "id": "gitlab_ci_token",
        "name": "GitLab CI/CD Token",
        "regex": re.compile(r'(?i)(?:gitlab[_\-\s]?)?ci[_\-\s]?token\s*[=:"\s\']+([A-Za-z0-9_\-]{20,})'),
        "severity": SEVERITY_HIGH,
        "category": "Source Control",
        "confidence": "medium",
        "remediation": "Rotate in GitLab project → Settings → CI/CD → Variables.",
    },
    {
        "id": "bitbucket_app_password",
        "name": "Bitbucket App Password",
        "regex": re.compile(r'(?i)bitbucket[_\-\s]?(?:app[_\-\s]?)?password\s*[=:"\s\']+([A-Za-z0-9+/=]{20,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Source Control",
        "confidence": "medium",
        "remediation": "Revoke in Bitbucket → Account Settings → App Passwords.",
    },

<<<<<<< HEAD
 
=======
    # ═══════════════════════════════════════════════════════
    # PAYMENT PROCESSORS
    # ═══════════════════════════════════════════════════════

>>>>>>> a427c87 (git push)
    {
        "id": "stripe_secret_key",
        "name": "Stripe Secret Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Roll immediately in Stripe Dashboard → Developers → API keys. This key can charge customers.",
    },
    {
        "id": "stripe_restricted_key",
        "name": "Stripe Restricted Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(rk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Roll in Stripe Dashboard. Store as environment variable.",
    },
    {
        "id": "stripe_webhook_secret",
        "name": "Stripe Webhook Secret",
        "regex": re.compile(r'(?<![A-Za-z0-9])(whsec_[A-Za-z0-9]{32,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Rotate in Stripe Dashboard → Developers → Webhooks.",
    },
    {
        "id": "stripe_publishable_key",
        "name": "Stripe Publishable Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(pk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_LOW,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Publishable keys are semi-public but should still be restricted by domain in Stripe settings.",
    },
    {
        "id": "paypal_secret",
        "name": "PayPal Client Secret",
        "regex": re.compile(r'(?i)(?:paypal|braintree)[_\-\s]?(?:secret|client_secret|access_token)\s*[=:"\s\']+([A-Za-z0-9_\-]{16,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "confidence": "medium",
        "remediation": "Revoke in PayPal Developer Dashboard and rotate credentials.",
    },
    {
        "id": "razorpay_key",
        "name": "Razorpay API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(rzp_live_[A-Za-z0-9]{14,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Revoke in Razorpay Dashboard → Settings → API Keys.",
    },
    {
        "id": "square_access_token",
        "name": "Square Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(EAAAE[A-Za-z0-9\-_]{59})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Payment",
        "confidence": "high",
        "remediation": "Revoke in Square Developer Dashboard → OAuth.",
    },

<<<<<<< HEAD
  
=======
    # ═══════════════════════════════════════════════════════
    # COMMUNICATION
    # ═══════════════════════════════════════════════════════
>>>>>>> a427c87 (git push)

    {
        "id": "twilio_account_sid",
        "name": "Twilio Account SID",
        "regex": re.compile(r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Rotate auth token in Twilio Console. Store credentials as environment variables.",
    },
    {
        "id": "twilio_auth_token",
        "name": "Twilio Auth Token",
        "regex": re.compile(r'(?i)twilio[_\-\s]?auth[_\-\s]?token\s*[=:"\s\']+([a-f0-9]{32})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Rotate immediately in Twilio Console.",
    },
    {
        "id": "sendgrid_api_key",
        "name": "SendGrid API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9.])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9.])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Revoke in SendGrid → Settings → API Keys. Create a restricted replacement key.",
    },
    {
        "id": "mailgun_api_key",
        "name": "Mailgun API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(key-[a-f0-9]{32})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Regenerate in Mailgun → Account → Security.",
    },
    {
        "id": "mailchimp_api_key",
        "name": "Mailchimp API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])([a-f0-9]{32}-us[0-9]{1,2})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Revoke in Mailchimp → Account → Extras → API Keys.",
    },
    {
        "id": "postmark_token",
        "name": "Postmark Server Token",
        "regex": re.compile(r'(?i)postmark[_\-\s]?(?:server[_\-\s]?)?(?:api[_\-\s]?)?token\s*[=:"\s\']+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Rotate in Postmark → Server → API Tokens.",
    },
    {
        "id": "slack_webhook",
        "name": "Slack Webhook URL",
        "regex": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Revoke in Slack → App → Incoming Webhooks. Generate a new webhook URL.",
    },
    {
        "id": "slack_token",
        "name": "Slack API Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(xox[baprs]-(?:[0-9]+-)+[a-z0-9]+)(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Revoke in Slack API dashboard and rotate.",
    },
    {
        "id": "discord_bot_token",
        "name": "Discord Bot Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])([MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Regenerate in Discord Developer Portal → Bot → Reset Token.",
    },
    {
        "id": "discord_webhook",
        "name": "Discord Webhook URL",
        "regex": re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Delete the webhook in Discord channel settings and create a new one.",
    },
    {
        "id": "telegram_bot_token",
        "name": "Telegram Bot Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])([0-9]{8,10}:[A-Za-z0-9_\-]{35})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Communication",
        "confidence": "high",
        "remediation": "Revoke via @BotFather → /revoke. Generate a new token.",
    },

<<<<<<< HEAD

=======
    # ═══════════════════════════════════════════════════════
    # DATABASES
    # ═══════════════════════════════════════════════════════
>>>>>>> a427c87 (git push)

    {
        "id": "db_connection_string",
        "name": "Database Connection String",
        "regex": re.compile(r'(?i)((?:mysql|postgresql|postgres|mongodb(?:\+srv)?|redis|mssql|oracle|sqlite|mariadb|cockroachdb|clickhouse):\/\/[^:]+:[^@\s"\'`]{3,}@[^\s"\'`]+)'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "confidence": "high",
        "remediation": "Rotate database credentials immediately. Use environment variables or a secrets manager.",
    },
    {
        "id": "mongodb_atlas_connection",
        "name": "MongoDB Atlas Connection String",
        "regex": re.compile(r'mongodb\+srv://[^:]+:[^@]+@[a-z0-9]+\.mongodb\.net'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "confidence": "high",
        "remediation": "Rotate credentials in MongoDB Atlas → Database Access. Enable IP allowlist.",
    },
    {
        "id": "redis_url",
        "name": "Redis URL with Password",
        "regex": re.compile(r'redis://:([^@\s"\'`]{6,})@[^\s"\'`]+:[0-9]+'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "confidence": "high",
        "remediation": "Rotate the Redis AUTH password and update the connection string.",
    },
    {
        "id": "generic_password_assignment",
        "name": "Hardcoded Password",
        "regex": re.compile(r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\'`\s]{8,})["\']'),
        "severity": SEVERITY_MEDIUM,
        "category": "Database",
        "confidence": "medium",
        "remediation": "Remove hardcoded password. Use environment variable: os.environ.get('DB_PASSWORD')",
    },
    {
        "id": "supabase_key",
        "name": "Supabase Service Role Key",
        "regex": re.compile(r'(?i)supabase[_\-\s]?(?:service[_\-\s]?role[_\-\s]?)?(?:key|secret)\s*[=:"\s\']+([A-Za-z0-9._\-]{100,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "confidence": "medium",
        "remediation": "Rotate in Supabase Dashboard → Settings → API. The service role key bypasses RLS.",
    },
    {
        "id": "supabase_anon_key",
        "name": "Supabase Anon Key",
        "regex": re.compile(r'(?i)supabase[_\-\s]?anon[_\-\s]?key\s*[=:"\s\']+([A-Za-z0-9._\-]{100,})'),
        "severity": SEVERITY_LOW,
        "category": "Database",
        "confidence": "medium",
        "remediation": "Anon keys are semi-public but ensure your RLS policies are correctly configured.",
    },
    {
        "id": "planetscale_password",
        "name": "PlanetScale Database Password",
        "regex": re.compile(r'(?i)pscale_pw_([A-Za-z0-9_\-]{43})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Database",
        "confidence": "high",
        "remediation": "Delete and regenerate in PlanetScale Dashboard → Passwords.",
    },

<<<<<<< HEAD
 
=======
    # ═══════════════════════════════════════════════════════
    # AUTH & IDENTITY
    # ═══════════════════════════════════════════════════════

>>>>>>> a427c87 (git push)
    {
        "id": "jwt_token",
        "name": "JSON Web Token",
        "regex": re.compile(r'(?<![A-Za-z0-9_\-])(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})(?![A-Za-z0-9_\-])'),
        "severity": SEVERITY_HIGH,
        "category": "Auth",
        "confidence": "high",
        "remediation": "Invalidate immediately. Never hardcode JWTs — they should be issued at runtime.",
    },
    {
        "id": "jwt_secret",
        "name": "JWT Secret / Signing Key",
        "regex": re.compile(r'(?i)jwt[_\-\s]?(?:secret|signing[_\-\s]?key|private[_\-\s]?key)\s*[=:"\s\']+([A-Za-z0-9_\-+/=!@#$%^&*]{20,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Auth",
        "confidence": "medium",
        "remediation": "Rotate the JWT secret immediately. All existing tokens signed with it are compromised.",
    },
    {
        "id": "oauth_client_secret",
        "name": "OAuth Client Secret",
        "regex": re.compile(r'(?i)client[_\-]?secret\s*[=:"\s\']+([A-Za-z0-9_\-]{16,64})'),
        "severity": SEVERITY_HIGH,
        "category": "Auth",
        "confidence": "medium",
        "remediation": "Rotate in your OAuth provider. Store in environment variables or a secrets manager.",
    },
    {
        "id": "auth0_client_secret",
        "name": "Auth0 Client Secret",
        "regex": re.compile(r'(?i)auth0[_\-\s]?(?:client[_\-\s]?)?secret\s*[=:"\s\']+([A-Za-z0-9_\-]{32,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Auth",
        "confidence": "medium",
        "remediation": "Rotate in Auth0 Dashboard → Applications → your app → Settings.",
    },
    {
        "id": "okta_api_token",
        "name": "Okta API Token",
        "regex": re.compile(r'(?i)okta[_\-\s]?(?:api[_\-\s]?)?token\s*[=:"\s\']+([A-Za-z0-9_\-]{40,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Auth",
        "confidence": "medium",
        "remediation": "Revoke in Okta Admin Console → Security → API → Tokens.",
    },
    {
        "id": "session_secret",
        "name": "Session Secret",
        "regex": re.compile(r'(?i)session[_\-\s]?secret\s*[=:"\s\']+([A-Za-z0-9_\-+/=!@#$%^&*]{20,})'),
        "severity": SEVERITY_HIGH,
        "category": "Auth",
        "confidence": "medium",
        "remediation": "Rotate the session secret. All existing sessions signed with it should be invalidated.",
    },

<<<<<<< HEAD
 
=======
    # ═══════════════════════════════════════════════════════
    # PRIVATE KEYS & CERTIFICATES
    # ═══════════════════════════════════════════════════════
>>>>>>> a427c87 (git push)

    {
        "id": "rsa_private_key",
        "name": "RSA Private Key",
        "regex": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "confidence": "high",
        "remediation": "Revoke and regenerate immediately. Never commit private keys to version control.",
    },
    {
        "id": "ec_private_key",
        "name": "EC Private Key",
        "regex": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "confidence": "high",
        "remediation": "Revoke and regenerate. Store in a hardware security module or secrets manager.",
    },
    {
        "id": "openssh_private_key",
        "name": "OpenSSH Private Key",
        "regex": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "confidence": "high",
        "remediation": "Revoke from all authorized_keys files. Generate a new key pair.",
    },
    {
        "id": "pkcs8_private_key",
        "name": "PKCS#8 Private Key",
        "regex": re.compile(r'-----BEGIN PRIVATE KEY-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "confidence": "high",
        "remediation": "Revoke and regenerate this key immediately.",
    },
    {
        "id": "pgp_private_key",
        "name": "PGP Private Key Block",
        "regex": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        "severity": SEVERITY_CRITICAL,
        "category": "Cryptography",
        "confidence": "high",
        "remediation": "Revoke this PGP key and generate a new one. Notify all parties that trusted it.",
    },

<<<<<<< HEAD
   
=======
    # ═══════════════════════════════════════════════════════
    # AI / ML SERVICES
    # ═══════════════════════════════════════════════════════

>>>>>>> a427c87 (git push)
    {
        "id": "openai_api_key",
        "name": "OpenAI API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "AI Services",
        "confidence": "high",
        "remediation": "Revoke in OpenAI Platform → API Keys immediately. Leaked keys can incur huge financial charges.",
    },
    {
        "id": "openai_api_key_generic",
        "name": "OpenAI API Key (generic format)",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk-[A-Za-z0-9]{48})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "AI Services",
        "confidence": "high",
        "remediation": "Revoke in OpenAI Platform → API Keys. Rotate and store as environment variable.",
    },
    {
        "id": "anthropic_api_key",
        "name": "Anthropic API Key",
        "regex": re.compile(r'(?<![A-Za-z0-9])(sk-ant-(?:api03-)?[A-Za-z0-9_\-]{40,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "AI Services",
        "confidence": "high",
        "remediation": "Revoke in Anthropic Console → API Keys immediately.",
    },
    {
        "id": "huggingface_token",
        "name": "HuggingFace Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(hf_[A-Za-z0-9]{34,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "AI Services",
        "confidence": "high",
        "remediation": "Revoke in HuggingFace → Settings → Access Tokens.",
    },
    {
        "id": "cohere_api_key",
        "name": "Cohere API Key",
        "regex": re.compile(r'(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key\s*[=:"\s\']+([A-Za-z0-9]{40})'),
        "severity": SEVERITY_HIGH,
        "category": "AI Services",
        "confidence": "medium",
        "remediation": "Revoke in Cohere Dashboard → API Keys.",
    },
    {
        "id": "replicate_api_key",
        "name": "Replicate API Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(r8_[A-Za-z0-9]{37})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "AI Services",
        "confidence": "high",
        "remediation": "Revoke in Replicate → Account Settings → API tokens.",
    },

<<<<<<< HEAD
=======
    # ═══════════════════════════════════════════════════════
    # INFRASTRUCTURE & DEVOPS
    # ═══════════════════════════════════════════════════════
>>>>>>> a427c87 (git push)

    {
        "id": "heroku_api_key",
        "name": "Heroku API Key",
        "regex": re.compile(r'(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key\s*[=:"\s\']+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke in Heroku Dashboard → Account Settings → API Key.",
    },
    {
        "id": "vercel_token",
        "name": "Vercel Access Token",
        "regex": re.compile(r'(?i)vercel[_\-\s]?(?:access[_\-\s]?)?token\s*[=:"\s\']+([A-Za-z0-9]{24,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "medium",
        "remediation": "Revoke in Vercel Dashboard → Settings → Tokens.",
    },
    {
        "id": "netlify_token",
        "name": "Netlify Access Token",
        "regex": re.compile(r'(?i)netlify[_\-\s]?(?:access[_\-\s]?)?token\s*[=:"\s\']+([A-Za-z0-9\-_]{40,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "medium",
        "remediation": "Revoke in Netlify → User settings → Applications → Personal access tokens.",
    },
    {
        "id": "railway_token",
        "name": "Railway API Token",
        "regex": re.compile(r'(?i)railway[_\-\s]?(?:api[_\-\s]?)?token\s*[=:"\s\']+([A-Za-z0-9\-_]{32,})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "medium",
        "remediation": "Revoke in Railway Dashboard → Account → Tokens.",
    },
    {
        "id": "doppler_token",
        "name": "Doppler Service Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(dp\.st\.[A-Za-z0-9_\-.]{40,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke in Doppler Dashboard → Project → Config → Service Tokens.",
    },
    {
        "id": "digitalocean_token",
        "name": "DigitalOcean Personal Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(dop_v1_[a-f0-9]{64})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke in DigitalOcean → API → Personal access tokens.",
    },
    {
        "id": "terraform_cloud_token",
        "name": "Terraform Cloud API Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke in Terraform Cloud → User Settings → Tokens.",
    },
    {
        "id": "vault_token",
        "name": "HashiCorp Vault Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(hvs\.[A-Za-z0-9]{24,})(?![A-Za-z0-9])'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke with: vault token revoke <token>. Audit what it was used for.",
    },
    {
        "id": "npm_token",
        "name": "npm Access Token",
        "regex": re.compile(r'(?<![A-Za-z0-9])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])'),
        "severity": SEVERITY_HIGH,
        "category": "Infrastructure",
        "confidence": "high",
        "remediation": "Revoke in npmjs.com → Access Tokens. An npm token can publish packages as you.",
    },
    {
        "id": "docker_auth",
        "name": "Docker Registry Auth",
        "regex": re.compile(r'"auth"\s*:\s*"([A-Za-z0-9+/=]{20,})"'),
        "severity": SEVERITY_HIGH,
        "category": "Infrastructure",
        "confidence": "medium",
        "remediation": "Rotate Docker registry credentials and use docker credential helpers instead.",
    },
    {
        "id": "circleci_token",
        "name": "CircleCI API Token",
        "regex": re.compile(r'(?i)circleci[_\-\s]?(?:api[_\-\s]?)?token\s*[=:"\s\']+([a-f0-9]{40})'),
        "severity": SEVERITY_CRITICAL,
        "category": "Infrastructure",
        "confidence": "medium",
        "remediation": "Revoke in CircleCI → User Settings → Personal API Tokens.",
    },

<<<<<<< HEAD
=======
    # ═══════════════════════════════════════════════════════
    # DATA / ANALYTICS
    # ═══════════════════════════════════════════════════════
>>>>>>> a427c87 (git push)

    {
        "id": "datadog_api_key",
        "name": "Datadog API Key",
        "regex": re.compile(r'(?i)(?:datadog|dd)[_\-\s]?api[_\-\s]?key\s*[=:"\s\']+([a-f0-9]{32})'),
        "severity": SEVERITY_HIGH,
        "category": "Analytics",
        "confidence": "medium",
        "remediation": "Revoke in Datadog → Organization Settings → API Keys.",
    },
    {
        "id": "segment_write_key",
        "name": "Segment Write Key",
        "regex": re.compile(r'(?i)segment[_\-\s]?(?:write[_\-\s]?)?key\s*[=:"\s\']+([A-Za-z0-9]{32,})'),
        "severity": SEVERITY_MEDIUM,
        "category": "Analytics",
        "confidence": "medium",
        "remediation": "Rotate in Segment → Sources → your source → Settings → API Keys.",
    },
    {
        "id": "sentry_dsn",
        "name": "Sentry DSN",
        "regex": re.compile(r'https://[a-f0-9]{32}@(?:o[0-9]+\.)?ingest\.sentry\.io/[0-9]+'),
        "severity": SEVERITY_MEDIUM,
        "category": "Analytics",
        "confidence": "high",
        "remediation": "Sentry DSNs are designed to be public-facing, but rotate if you want to prevent spam events.",
    },
    {
        "id": "mixpanel_token",
        "name": "Mixpanel Project Token",
        "regex": re.compile(r'(?i)mixpanel[_\-\s]?token\s*[=:"\s\']+([a-f0-9]{32})'),
        "severity": SEVERITY_MEDIUM,
        "category": "Analytics",
        "confidence": "medium",
        "remediation": "Project tokens are semi-public; rotate the secret key if also exposed.",
    },

<<<<<<< HEAD
=======
    # ═══════════════════════════════════════════════════════
    # GENERIC HIGH-ENTROPY (always need entropy validation)
    # ═══════════════════════════════════════════════════════

>>>>>>> a427c87 (git push)
    {
        "id": "generic_api_key",
        "name": "Generic API Key",
        "regex": re.compile(r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|app[_\-]?secret|secret[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
        "severity": SEVERITY_MEDIUM,
        "category": "Generic",
        "confidence": "medium",
        "remediation": "Identify the service this key belongs to and rotate it. Move to environment variable.",
    },
    {
        "id": "generic_token",
        "name": "Generic Access Token",
        "regex": re.compile(r'(?i)(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|api[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?'),
        "severity": SEVERITY_MEDIUM,
        "category": "Generic",
        "confidence": "medium",
        "remediation": "Rotate with the issuing service. Store in environment variables.",
    },
    {
        "id": "generic_secret",
        "name": "Generic Secret Value",
        "regex": re.compile(r'(?i)(?:app[_\-]?secret|signing[_\-]?secret|webhook[_\-]?secret|encryption[_\-]?key|master[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-+/=!@#$%^&*]{20,})["\']'),
        "severity": SEVERITY_MEDIUM,
        "category": "Generic",
        "confidence": "medium",
        "remediation": "Identify and rotate this secret. Store in a secrets manager.",
    },
]

<<<<<<< HEAD
# ─False positive filters 
=======
# ── False positive filters ─────────────────────────────────────────────────────
# Match against the captured value — if any pattern matches, skip the finding
>>>>>>> a427c87 (git push)

PLACEHOLDER_PATTERNS = [
    re.compile(r'(?i)(your[_\-]?|my[_\-]?|the[_\-]?|an?[_\-]?|this[_\-]?|some[_\-]?)(api[_\-]?key|secret|token|password|key)'),
    re.compile(r'(?i)(insert|replace|put|add|enter|type)[_\-\s]+(here|this|your|the|it)'),
    re.compile(r'(?i)(example|sample|test|demo|fake|dummy|placeholder|mock|stub|temp|tmp|dev|staging)'),
    re.compile(r'\$\{[^}]+\}|<%[^%]+%>|\{\{[^}]+\}\}|<[A-Z_]+>|%[A-Z_]+%'),
    re.compile(r'(?i)(change[_\-]?me|todo|fixme|replace[_\-]?me|fill[_\-]?in|tbd|n/?a|not[_\-]?set)'),
    re.compile(r'x{6,}|0{8,}|1{8,}|a{6,}'),
    re.compile(r'(?i)(local|localhost|127\.0\.0\.1|0\.0\.0\.0)'),
]

# Extensions to skip in directory scans
<<<<<<< HEAD
# NOTE: .txt, .md, .env etc. are NOT skipped  they commonly contain real secrets
=======
# NOTE: .txt, .md, .env etc. are NOT skipped — they commonly contain real secrets
>>>>>>> a427c87 (git push)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
    '.pdf', '.zip', '.tar', '.gz', '.bz2', '.xz', '.rar', '.7z',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
    '.ttf', '.woff', '.woff2', '.eot',
    '.pyc', '.pyo', '.class',
    '.min.js', '.min.css',
    '.lock', '.sum',
    '.map',
}

# Directory names to always skip
SKIP_PATHS = {
    'node_modules', '.git', '__pycache__', 'dist', 'build', 'out',
    'vendor', '.venv', 'venv', 'env', 'virtualenv',
    'test_fixtures', 'fixtures', 'mocks', '__mocks__',
    '.next', '.nuxt', '.svelte-kit', 'coverage', '.nyc_output',
    'bower_components', 'jspm_packages',
}

<<<<<<< HEAD
# Exact filenames that are almost always example
=======
# Exact filenames that are almost always example/test files
>>>>>>> a427c87 (git push)
SKIP_FILENAMES = {
    '.env.example', '.env.sample', '.env.test', '.env.template',
    'example.env', 'sample.env', 'template.env',
    'secrets.example.yaml', 'secrets.example.json',
    'config.example.json', 'config.example.yaml',
    '.env.local.example',
}
