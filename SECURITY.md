# Security Policy

## Overview

The NOMYO Client implements end-to-end encryption for secure communication with the NOMYO Router.

## Security Best Practices

### 1. Always Use HTTPS in Production

The client MUST connect using HTTPS in production environments:

```python
# ✅ SECURE (Production)
client = SecureChatCompletion(base_url="https://api.nomyo.ai:12434")

# ⚠️ INSECURE (Local development only)
client = SecureChatCompletion(base_url="http://localhost:12434", allow_http=True)
```

**Important:** The `allow_http=True` parameter must be explicitly set to enable HTTP connections for local development. Without this parameter, HTTP connections will raise a `SecurityError` to prevent accidental use of insecure connections.

HTTP connections are vulnerable to man-in-the-middle attacks where an attacker could intercept and substitute the server's public key.

### 2. Protect Private Keys

**Password Protection:**
```python
# Generate keys with password protection
await client.generate_keys(save_to_file=True, password="strong_password_here")

# Load password-protected keys
await client.load_keys("client_keys/private_key.pem", password="strong_password_here")
```

**File Permissions:**
- Private keys are automatically saved with 0600 permissions (owner read/write only)
- Never commit private keys to version control
- Add `client_keys/` to your `.gitignore`

### 3. Key Management

**Key Rotation:**
- Regularly rotate RSA key pairs (recommended: every 90 days)
- Generate new keys when changing environments (dev → staging → production)

**Key Storage:**
- Store keys outside the project directory in production
- Use environment variables or secrets management systems
- Never hardcode keys in source code

### 4. Validate Server Certificates

The client enforces HTTPS certificate verification by default. Do not disable this in production.

## Security Features

- RSA-4096 with OAEP padding (SHA-256)
- AES-256-GCM for payload encryption
- Cryptographically secure random number generation (using `secrets` module)
- HTTPS with certificate verification
- Input validation and size limits (10MB max payload)
- Secure error handling (no information leakage)
- Key validation (minimum 2048-bit RSA keys)

## Local Development

For local development with HTTP servers:

```python
# Explicitly allow HTTP for local development
client = SecureChatCompletion(
    base_url="http://localhost:12434",
    allow_http=True  # Required for HTTP
)
```

This will display warnings but allow the connection to proceed.

## Reporting Security Issues

Report security vulnerabilities responsibly:
- Do NOT create public GitHub issues
- Contact: security@nomyo.ai
- Include detailed vulnerability information
- Allow time for remediation before disclosure
