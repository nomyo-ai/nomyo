# NOMYO Secure Python Chat Client

**OpenAI-compatible secure chat client with end-to-end encryption with NOMYO Inference Endpoints**

🔒 **All prompts and responses are automatically encrypted and decrypted**
🔑 **Uses hybrid encryption (AES-256-GCM + RSA-OAEP with 4096-bit keys)**
🔄 **Drop-in replacement for OpenAI's ChatCompletion API**

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Use the client (same API as OpenAI)

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    # Initialize client (defaults to http://api.nomyo.ai:12434)
    client = SecureChatCompletion(base_url="http://api.nomyo.ai:12434")

    # Simple chat completion
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello! How are you today?"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

# Run the async function
asyncio.run(main())
```

### 3. Run tests

```bash
python3 test.py
```

## 🔐 Security Features

### Hybrid Encryption

- **Payload encryption**: AES-256-GCM (authenticated encryption)
- **Key exchange**: RSA-OAEP with SHA-256
- **Key size**: 4096-bit RSA keys
- **All communication**: End-to-end encrypted

### Key Management

- Automatic key generation and management
- Keys stored with restricted permissions (600 for private key)
- Optional password protection for private keys
- Key persistence across sessions

## 🔄 OpenAI Compatibility

The `SecureChatCompletion` class provides **exact API compatibility** with OpenAI's `ChatCompletion.create()` method.

### Supported Parameters

All standard OpenAI parameters are supported:

- `model`: Model identifier
- `messages`: List of message objects
- `temperature`: Sampling temperature (0-2)
- `max_tokens`: Maximum tokens to generate
- `top_p`: Nucleus sampling
- `frequency_penalty`: Frequency penalty
- `presence_penalty`: Presence penalty
- `stop`: Stop sequences
- `n`: Number of completions
- `stream`: Streaming (not yet implemented)
- `tools`: Tool definitions
- `tool_choice`: Tool selection strategy
- `user`: User identifier
- And more...

### Response Format

Responses follow the OpenAI format exactly, with an additional `_metadata` field for debugging and security information:

```python
{
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "created": 1234567890,
    "model": "Qwen/Qwen3-0.6B",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello! I'm doing well, thank you for asking.",
                "tool_calls": [...]  # if tools were used
            },
            "finish_reason": "stop"
        }
    ],
    "usage": {
        "prompt_tokens": 10,
        "completion_tokens": 20,
        "total_tokens": 30
    },
    "_metadata": {
        "payload_id": "openai-compat-abc123",  # Unique identifier for this request
        "processed_at": 1765250382,  # Timestamp when server processed the request
        "is_encrypted": True,  # Indicates this response was decrypted
        "encryption_algorithm": "hybrid-aes256-rsa4096",  # Encryption method used
        "response_status": "success"  # Status of the decryption/processing
    }
}
```

The `_metadata` field contains security-related information about the encrypted communication and is automatically added to all responses.

## 🛠️ Usage Examples

### Basic Chat

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(base_url="http://api.nomyo.ai:12434")

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

### With Tools

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(base_url="http://api.nomyo.ai:12434")

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "What's the weather in Paris?"}
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather information",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"}
                        },
                        "required": ["location"]
                    }
                }
            }
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

### Using acreate() Alias

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(base_url="http://api.nomyo.ai:12434")

    response = await client.acreate(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello!"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

## 📦 Dependencies

See `requirements.txt` for the complete list:

- `cryptography`: Cryptographic primitives (RSA, AES, etc.)
- `httpx`: Async HTTP client
- `anyio`: Async compatibility layer

## 🔧 Configuration

### Custom Base URL

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(base_url="http://NOMYO-Pro-Router:12434")
    # ... rest of your code
    asyncio.run(main())
```

### Key Management

Keys are automatically generated on first use and stored in `client_keys/` directory.

#### Generate Keys Manually

```python
import asyncio
from nomyo.SecureCompletionClient import SecureCompletionClient

async def main():
    client = SecureCompletionClient()
    await client.generate_keys(save_to_file=True, password="your-password")

asyncio.run(main())
```

#### Load Existing Keys

```python
import asyncio
from nomyo.SecureCompletionClient import SecureCompletionClient

async def main():
    client = SecureCompletionClient()
    await client.load_keys("client_keys/private_key.pem", "client_keys/public_key.pem", password="your-password")

asyncio.run(main())
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
python3 test.py
```

Tests verify:

- ✅ OpenAI API compatibility
- ✅ Basic chat completion
- ✅ Tool usage
- ✅ All OpenAI parameters
- ✅ Async methods
- ✅ Error handling

## 📚 API Reference

### SecureChatCompletion

#### Constructor

```python
SecureChatCompletion(base_url: str = "http://api.nomyo.ai:12434")
```

#### Methods

- `create(model, messages, **kwargs)`: Create a chat completion
- `acreate(model, messages, **kwargs)`: Async alias for create()

### SecureCompletionClient

#### Constructor

```python
SecureCompletionClient(router_url: str = "http://api.nomyo.ai:12434")
```

#### Methods

- `generate_keys(save_to_file=False, key_dir="client_keys", password=None)`: Generate RSA key pair
- `load_keys(private_key_path, public_key_path=None, password=None)`: Load keys from files
- `fetch_server_public_key()`: Fetch server's public key
- `encrypt_payload(payload)`: Encrypt a payload
- `decrypt_response(encrypted_response, payload_id)`: Decrypt a response
- `send_secure_request(payload, payload_id)`: Send encrypted request and receive decrypted response

## 📝 Notes

### Security Best Practices

- Always use password protection for private keys in production
- Keep private keys secure (permissions set to 600)
- Never share your private key
- Verify server's public key fingerprint before first use

### Performance

- Key generation takes ~1-2 seconds (one-time operation)
- Encryption/decryption adds minimal overhead (~10-20ms per request)

### Compatibility

- Works with any OpenAI-compatible code
- No changes needed to existing OpenAI client code
- Simply replace `openai.ChatCompletion.create()` with `SecureChatCompletion.create()`

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests on the project repository.

## 📄 License

See LICENSE file for licensing information.

## 📞 Support

For questions or issues, please refer to the project documentation or open an issue.
