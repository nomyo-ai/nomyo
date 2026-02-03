# Security Guide

## Overview

The NOMYO client provides end-to-end encryption for all communications between your application and the NOMYO inference endpoints. This ensures that your prompts and responses are protected from unauthorized access or interception.

## Encryption Mechanism

### Hybrid Encryption

The client uses a hybrid encryption approach combining:

1. **AES-256-GCM** for payload encryption (authenticated encryption)
2. **RSA-OAEP** for key exchange (4096-bit keys)

This provides both performance (AES for data) and security (RSA for key exchange).

### Key Management

#### Automatic Key Generation

Keys are automatically generated in memory on first use/session init. The client handles all key management internally.

#### Key Persistence (optional)

Keys *can* be saved to the `client_keys/` directory for reuse (i.e. in dev scenarios) across sessions [not recommend]:

```python
# Generate keys and save to file
await client.generate_keys(save_to_file=True, password="your-password")
```

#### Password Protection

Saved private keys should be password-protected in all environments:

```python
await client.generate_keys(save_to_file=True, password="your-strong-password")
```

## Secure Memory Protection

### Ephemeral AES Keys

- **Per-request encryption keys**: A unique AES-256 key is generated for each request
- **Automatic rotation**: AES keys are never reused - a fresh key is created for every encryption operation
- **Forward secrecy**: Compromise of one AES key only affects that single request
- **Secure generation**: AES keys are generated using cryptographically secure random number generation (`secrets.token_bytes`)
- **Automatic cleanup**: AES keys are zeroed from memory immediately after use

### Memory Protection

The client can use secure memory protection to:

- Prevent plaintext payloads from being swapped to disk
- Guarantee memory is zeroed after encryption
- Prevent sensitive data from being stored in memory dumps

## Security Best Practices

### For Production Use

1. **Always use password protection** for private keys
2. **Keep private keys secure** (permissions set to 600 - owner-only access)
3. **Never share your private key**
4. **Verify server's public key fingerprint** before first use
5. **Use HTTPS connections** (never allow HTTP in production)

### Key Management

```python
# Generate keys with password protection
await client.generate_keys(
    save_to_file=True,
    key_dir="client_keys",
    password="strong-password-here"
)

# Load existing keys with password
await client.load_keys(
    "client_keys/private_key.pem",
    "client_keys/public_key.pem",
    password="strong-password-here"
)
```

### Security Tiers

The client supports three security tiers:

- **Standard**: General secure inference
- **High**: Sensitive business data
- **Maximum**: Maximum isolation (HIPAA PHI, classified data)

```python
# Use different security tiers
response = await client.create(
    model="Qwen/Qwen3-0.6B",
    messages=[{"role": "user", "content": "My sensitive data"}],
    security_tier="high"
)
```

## Security Features

### End-to-End Encryption

All prompts and responses are automatically encrypted and decrypted, ensuring:

- No plaintext data is sent over the network
- No plaintext data is stored in memory
- No plaintext data is stored on disk

### Forward Secrecy

Each request uses a unique AES key, ensuring that:

- Compromise of one request's key only affects that request
- Previous requests remain secure even if current key is compromised

### Key Exchange Security

RSA-OAEP key exchange with 4096-bit keys provides:

- Strong encryption for key exchange
- Protection against known attacks
- Forward secrecy for key material

### Memory Protection

Secure memory features:

- Prevents plaintext from being swapped to disk
- Guarantees zeroing of sensitive memory
- Prevents memory dumps from containing sensitive data

## Compliance Considerations

### HIPAA Compliance

The client can be used for HIPAA-compliant applications when:

- Keys are password-protected
- HTTPS is used for all connections
- Private keys are stored securely
- Appropriate security measures are in place

### Data Classification

- **Standard**: General data
- **High**: Sensitive business data
- **Maximum**: Classified data (PHI, PII, etc.)

## Security Testing

The client includes comprehensive security testing:

- All encryption/decryption operations are tested
- Key management is verified
- Memory protection is validated
- Error handling is tested

Run the test suite to verify security:

```bash
python3 test.py
```

## Troubleshooting Security Issues

### Common Issues

1. **Key loading failures**: Ensure private key file permissions are correct (600)
2. **Connection errors**: Verify HTTPS is used for production
3. **Decryption failures**: Check that the correct API key is used
4. **Memory protection errors**: SecureMemory module may not be available on all systems

### Debugging

The client adds metadata to responses that can help with debugging:

```python
response = await client.create(
    model="Qwen/Qwen3-0.6B",
    messages=[{"role": "user", "content": "Hello"}]
)

print(response["_metadata"])  # Contains security-related information
```

### Logging

Enable logging to see security operations:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```
