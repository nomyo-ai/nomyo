import os
import uuid
from typing import Dict, Any, List, Optional
from .SecureCompletionClient import SecureCompletionClient

# Import secure memory module for configuration
try:
    from .SecureMemory import disable_secure_memory, enable_secure_memory
    _SECURE_MEMORY_AVAILABLE = True
except ImportError:
    _SECURE_MEMORY_AVAILABLE = False

class SecureChatCompletion:
    """
    OpenAI-compatible secure chat completion client.

    This class provides the same interface as OpenAI's ChatCompletion.create()
    method, but automatically encrypts all requests and decrypts all responses
    for secure communication with the NOMYO Router's /v1/chat/secure_completion
    endpoint.

    Security Features:
    - End-to-end encryption (AES-256-GCM + RSA-OAEP)
    - Secure memory protection (prevents memory swapping and guarantees zeroing)
    - HTTPS enforcement (with optional HTTP for local development)
    - Automatic key management

    Usage:
        ```python
        # Create a client instance
        client = SecureChatCompletion(base_url="https://api.nomyo.ai:12435")

        # Simple chat completion
        response = await client.create(
            model="Qwen/Qwen3-0.6B",
            messages=[
                {"role": "user", "content": "What is the capital of France?"}
            ],
            temperature=0.7
        )

        # With tools
        response = await client.create(
            model="Qwen/Qwen3-0.6B",
            messages=[
                {"role": "user", "content": "What's the weather in Paris?"}
            ],
            tools=[...],
            temperature=0.7
        )
        ```
    """

    def __init__(self, base_url: str = "https://api.nomyo.ai:12435", allow_http: bool = False, api_key: Optional[str] = None, secure_memory: bool = True, key_dir: Optional[str] = None):
        """
        Initialize the secure chat completion client.

        Args:
            base_url: Base URL of the NOMYO Router (must use HTTPS for production)
                     This parameter is named 'base_url' for OpenAI compatibility.
            allow_http: Allow HTTP connections (ONLY for local development, never in production)
            api_key: Optional API key for bearer authentication. If provided, it will be
                     used for all requests made with this client.
            secure_memory: Enable secure memory protection (default: True).
                          When enabled, prevents plaintext payloads from being swapped to disk
                          and guarantees memory is zeroed after encryption.
                          Set to False for testing or when security is not required.
            key_dir: Directory to load/save RSA keys. If None, ephemeral keys are
                     generated in memory for this session only.
        """
        self.client = SecureCompletionClient(router_url=base_url, allow_http=allow_http)
        self._keys_initialized = False
        self.api_key = api_key
        self._key_dir = key_dir
        self._secure_memory_enabled = secure_memory

        # Configure secure memory if available
        if _SECURE_MEMORY_AVAILABLE:
            if secure_memory:
                enable_secure_memory()
            else:
                disable_secure_memory()
        elif secure_memory:
            import warnings
            warnings.warn(
                "Secure memory requested but not available. "
                "Falling back to standard memory handling.",
                UserWarning,
                stacklevel=2
            )

    def _ensure_keys(self):
        """Ensure keys are loaded or generated."""
        if self._keys_initialized:
            return
        if self._key_dir is not None:
            private_key_path = os.path.join(self._key_dir, "private_key.pem")
            public_key_path = os.path.join(self._key_dir, "public_key.pem")
            try:
                self.client.load_keys(private_key_path, public_key_path)
                self._keys_initialized = True
                return
            except Exception:
                self.client.generate_keys(save_to_file=True, key_dir=self._key_dir)
        else:
            self.client.generate_keys()
        self._keys_initialized = True

    async def create(self, model: str, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Creates a new chat completion for the provided messages and parameters.

        This method provides the same interface as OpenAI's ChatCompletion.create()
        but automatically handles encryption and decryption for secure communication.

        Args:
            model: The model to use for the chat completion.
            messages: A list of message objects. Each message has a role ("system",
                "user", or "assistant") and content.
            **kwargs: Additional parameters that can be passed to the API.
                Supported parameters include:
                - temperature: float (0-2)
                - max_tokens: int
                - tools: List of tool definitions
                - tool_choice: str ("auto", "none", or specific tool name)
                - stop: Union[str, List[str]]
                - presence_penalty: float
                - frequency_penalty: float
                - logit_bias: Dict[str, float]
                - user: str
                - base_url: str (alternative to initializing with router_url)
                - security_tier: str ("standard", "high", or "maximum")
                    Controls hardware routing and security level:
                    * "standard": general secure inference
                    * "high": sensitive business data
                    * "maximum": maximum isolation (PHI, classified data)
                    If not specified, server uses default based on model name mapping.

        Returns:
            A dictionary containing the chat completion response with the following structure:
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

        Raises:
            ValueError: If required parameters are missing or invalid.
            ConnectionError: If the connection to the router fails.
            Exception: For other errors during the request.
        """
        # Extract non-payload kwargs before building the payload dict
        base_url = kwargs.pop("base_url", None)
        security_tier = kwargs.pop("security_tier", None)
        api_key_override = kwargs.pop("api_key", None)

        # Use the instance's client unless base_url is explicitly overridden
        if base_url is not None:
            temp_client = type(self)(
                base_url=base_url,
                allow_http=self.client.allow_http,
                api_key=self.api_key,
                secure_memory=self._secure_memory_enabled,
                key_dir=self._key_dir,
            )
            instance = temp_client
        else:
            instance = self

        # Ensure keys are available (synchronous)
        instance._ensure_keys()

        # Build payload — api_key is intentionally excluded (sent as Bearer header)
        payload = {
            "model": model,
            "messages": messages,
            **kwargs
        }

        payload_id = str(uuid.uuid4())
        request_api_key = api_key_override if api_key_override is not None else instance.api_key

        # Send secure request with security tier
        response = await instance.client.send_secure_request(payload, payload_id, request_api_key, security_tier)

        return response

    async def acreate(self, model: str, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        Async alias for create() method.

        This provides the same functionality as create() but with an explicit
        async name, following OpenAI's naming conventions.

        Args:
            Same as create() method.

        Returns:
            Same as create() method.
        """
        return await self.create(model, messages, **kwargs)
