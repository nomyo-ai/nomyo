# NOMYO Secure Client Documentation

This documentation provides comprehensive information about using the NOMYO Secure Python Chat Client, a drop-in replacement for OpenAI's ChatCompletion API with end-to-end (E2E) encryption.
To use this client library you need a paid subscribtion on [NOMYO Inference](https://chat.nomyo.ai/).

## Overview

The NOMYO Secure Client provides:

- **End-to-end encryption** using hybrid encryption (AES-256-GCM + RSA-OAEP)
- **OpenAI API compatibility** - same interface as OpenAI's ChatCompletion
- **Secure memory protection** - prevents plaintext from being swapped to disk
- **Automatic key management** - handles key generation and loading automatically
- **HTTPS enforcement** - secure communication by default

## Quick Start

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    # Initialize client (defaults to https://api.nomyo.ai)
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Simple chat completion
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello! How are you today?"}
        ],
        security_tier="standard", # optional: standard, high or maximum
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

# Run the async function
asyncio.run(main())
```

## Documentation Structure

1. [Installation](installation.md) - How to install and set up the client
2. [Getting Started](getting-started.md) - Quick start guide with examples
3. [API Reference](api-reference.md) - Complete API documentation
4. [Security Guide](security-guide.md) - Security features and best practices
5. [Examples](examples.md) - Advanced usage scenarios
6. [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Key Features

- **OpenAI Compatibility**: Use the same API as OpenAI's ChatCompletion
- **End-to-End Encryption**: All prompts and responses are automatically encrypted/decrypted
- **Secure Memory Protection**: Prevents sensitive data from being swapped to disk
- **Automatic Key Management**: Keys are generated and loaded automatically
- **Flexible Security Tiers**: Control security levels for different data types
