"""
Semgrep test fixtures for secrets/credentials rules.
Run with: semgrep --test semgrep_rules/
"""

# ---------------------------------------------------------------------------
# SEC-001: AWS Access Key ID
# ---------------------------------------------------------------------------

def aws_key_id_violation():
    # ruleid: sec-aws-access-key-id
    key = "AKIAIOSFODNN7EXAMPLE1A"
    return key


def aws_key_id_clean():
    # ok: sec-aws-access-key-id
    key = "some-other-identifier-here"
    return key


# ---------------------------------------------------------------------------
# SEC-002: AWS Secret Access Key
# ---------------------------------------------------------------------------

def aws_secret_violation():
    # ruleid: sec-aws-secret-access-key, sec-hardcoded-credential
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    return aws_secret_access_key


def aws_secret_clean():
    # ok: sec-aws-secret-access-key
    region = "us-east-1"
    return region


# ---------------------------------------------------------------------------
# SEC-003: OpenAI API key
# ---------------------------------------------------------------------------

def openai_key_violation():
    # ruleid: sec-openai-api-key
    key = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"
    return key


def openai_key_clean():
    # ok: sec-openai-api-key
    key = "sk-short"
    return key


# ---------------------------------------------------------------------------
# SEC-004: GitHub personal access token
# ---------------------------------------------------------------------------

def github_token_violation():
    # ruleid: sec-github-token
    token = "ghp_abcdefghijklmnopqrstuvwxyz123456789012"
    return token


def github_token_clean():
    # ok: sec-github-token
    token = "github_token_placeholder"
    return token


# ---------------------------------------------------------------------------
# SEC-005: Stripe live secret key
# ---------------------------------------------------------------------------

def stripe_key_violation():
    # ruleid: sec-stripe-key
    stripe_key = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"
    return stripe_key


def stripe_key_clean():
    # ok: sec-stripe-key
    stripe_key = "sk_test_xxxxxxxxxxxxxxxxxxxxxxxx"
    return stripe_key


# ---------------------------------------------------------------------------
# SEC-006: Google API key
# ---------------------------------------------------------------------------

def google_key_violation():
    # ruleid: sec-google-api-key
    google_key = "AIzaSyDabcdefghijklmnopqrstuvwxyz012345"
    return google_key


def google_key_clean():
    # ok: sec-google-api-key
    placeholder = "your-api-key-here"
    return placeholder


# ---------------------------------------------------------------------------
# SEC-007: PEM private key
# ---------------------------------------------------------------------------

def private_key_violation():
    # ruleid: sec-private-key
    key = "-----BEGIN RSA PRIVATE KEY-----"
    return key


def private_key_clean():
    # ok: sec-private-key
    key = "-----BEGIN CERTIFICATE-----"
    return key


# ---------------------------------------------------------------------------
# SEC-008: Hardcoded credentials
# ---------------------------------------------------------------------------

def hardcoded_password_violation():
    # ruleid: sec-hardcoded-credential
    password = "supersecret123"
    return password


def hardcoded_api_key_violation():
    # ruleid: sec-hardcoded-credential
    api_key = "my-hardcoded-api-key"
    return api_key


def hardcoded_credential_clean():
    # ok: sec-hardcoded-credential
    username = "service-account"
    return username


# ---------------------------------------------------------------------------
# SEC-009: Slack token
# ---------------------------------------------------------------------------

def slack_token_violation():
    # ruleid: sec-slack-token
    bot_token = "xoxb-000000000-xxxxxxxxxxxxxxxx"
    return bot_token


def slack_token_clean():
    # ok: sec-slack-token
    channel_id = "C1234567890"
    return channel_id


# ---------------------------------------------------------------------------
# SEC-010: Database connection string with embedded credentials
# ---------------------------------------------------------------------------

def db_url_violation():
    # ruleid: sec-database-url-credentials
    db_url = "postgresql://user:password@localhost:5432/mydb"
    return db_url


def db_url_clean():
    # ok: sec-database-url-credentials
    db_url = "postgresql://localhost:5432/mydb"
    return db_url


def mysql_url_violation():
    # ruleid: sec-database-url-credentials
    db_url = "mysql://admin:secret123@db.example.com/app"
    return db_url
