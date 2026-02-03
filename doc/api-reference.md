# API Reference

## SecureChatCompletion Class

The `SecureChatCompletion` class is the main entry point for using the NOMYO secure client. It provides the same interface as OpenAI's ChatCompletion API with end-to-end encryption.

### Constructor

```python
SecureChatCompletion(
    base_url: str = "https://api.nomyo.ai",
    allow_http: bool = False,
    api_key: Optional[str] = None,
    secure_memory: bool = True
)
```

**Parameters:**

- `base_url` (str): Base URL of the NOMYO Router (must use HTTPS for production)
- `allow_http` (bool): Allow HTTP connections (ONLY for local development, never in production)
- `api_key` (Optional[str]): Optional API key for bearer authentication
- `secure_memory` (bool): Enable secure memory protection (default: True)

### Methods

#### create(model, messages, **kwargs)

Creates a new chat completion for the provided messages and parameters.

**Parameters:**

- `model` (str): The model to use for the chat completion
- `messages` (List[Dict]): A list of message objects. Each message has a role ("system", "user", or "assistant") and content
- `**kwargs`: Additional parameters that can be passed to the API

**Supported OpenAI Parameters:**

- `temperature` (float): Sampling temperature (0-2)
- `max_tokens` (int): Maximum tokens to generate
- `top_p` (float): Nucleus sampling
- `frequency_penalty` (float): Frequency penalty
- `presence_penalty` (float): Presence penalty
- `stop` (Union[str, List[str]]): Stop sequences
- `n` (int): Number of completions
- `stream` (bool): Streaming always = False to minimize de-/encryption overhead 
- `tools` (List): Tool definitions
- `tool_choice` (str): Tool selection strategy
- `user` (str): User identifier
- `security_tier` (str): Security level ("standard", "high", or "maximum")

**Returns:**
A dictionary containing the chat completion response with the following structure:

```python
{
    "id": str,
    "object": "chat.completion",
    "created": int,
    "model": str,
    "choices": [
        {
            "index": int,
            "message": {
                "role": str,
                "content": str,
                "tool_calls": List[Dict]  # if tools were used
            },
            "finish_reason": str
        }
    ],
    "usage": {
        "prompt_tokens": int,
        "completion_tokens": int,
        "total_tokens": int
    }
}
```

#### acreate(model, messages, **kwargs)

Async alias for create() method.

**Parameters:** Same as create() method

**Returns:** Same as create() method

## SecureCompletionClient Class

The `SecureCompletionClient` class handles the underlying encryption, key management, and API communication.

### Constructor

```python
SecureCompletionClient(router_url: str = "https://api.nomyo.ai:12434", allow_http: bool = False)
```

**Parameters:**

- `router_url` (str): Base URL of the NOMYO Router (must use HTTPS for production)
- `allow_http` (bool): Allow HTTP connections (ONLY for local development, never in production)

### Methods

#### generate_keys(save_to_file: bool = False, key_dir: str = "client_keys", password: Optional[str] = None)

Generate RSA key pair for secure communication.

**Parameters:**

- `save_to_file` (bool): Whether to save keys to files
- `key_dir` (str): Directory to save keys (if save_to_file is True)
- `password` (Optional[str]): Optional password to encrypt private key

#### load_keys(private_key_path: str, public_key_path: Optional[str] = None, password: Optional[str] = None)

Load RSA keys from files.

**Parameters:**

- `private_key_path` (str): Path to private key file
- `public_key_path` (Optional[str]): Path to public key file (optional, derived from private key if not provided)
- `password` (Optional[str]): Optional password for encrypted private key

#### fetch_server_public_key()

Fetch the server's public key from the /pki/public_key endpoint.

**Returns:**
Server's public key as PEM string

#### encrypt_payload(payload: Dict[str, Any])

Encrypt a payload using hybrid encryption (AES-256-GCM + RSA-OAEP).

**Parameters:**

- `payload` (Dict[str, Any]): Dictionary containing the chat completion request

**Returns:**
Encrypted payload as bytes

#### decrypt_response(encrypted_response: bytes, payload_id: str)

Decrypt a response from the secure endpoint.

**Parameters:**

- `encrypted_response` (bytes): Encrypted response bytes
- `payload_id` (str): Payload ID for metadata verification

**Returns:**
Decrypted response dictionary

#### send_secure_request(payload: Dict[str, Any], payload_id: str, api_key: Optional[str] = None, security_tier: Optional[str] = None)

Send a secure chat completion request to the router.

**Parameters:**

- `payload` (Dict[str, Any]): Chat completion request payload
- `payload_id` (str): Unique identifier for this request
- `api_key` (Optional[str]): Optional API key for bearer authentication
- `security_tier` (Optional[str]): Optional security tier for routing

**Returns:**
Decrypted response from the LLM

## Exception Classes

### APIError

Base class for all API-related errors.

### AuthenticationError

Raised when authentication fails (e.g., invalid API key).

### InvalidRequestError

Raised when the request is invalid (HTTP 400).

### APIConnectionError

Raised when there's a connection error.

### RateLimitError

Raised when rate limit is exceeded (HTTP 429).

### ServerError

Raised when the server returns an error (HTTP 500).

### SecurityError

Raised when a security violation is detected.
