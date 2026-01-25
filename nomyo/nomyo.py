import uuid
from typing import Dict, Any, List, Optional
from .SecureCompletionClient import SecureCompletionClient, APIError, AuthenticationError, InvalidRequestError, APIConnectionError, RateLimitError, ServerError

# Import secure memory module for configuration
try:
    from .SecureMemory import get_memory_protection_info, disable_secure_memory, enable_secure_memory
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
        client = SecureChatCompletion(base_url="http://api.nomyo.ai:12434")

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

    def __init__(self, base_url: str = "https://api.nomyo.ai:12434", allow_http: bool = False, api_key: Optional[str] = None, secure_memory: bool = True):
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
        """

        self.client = SecureCompletionClient(router_url=base_url, allow_http=allow_http)
        self._keys_initialized = False
        self.api_key = api_key

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

    async def _ensure_keys(self):
        """Ensure keys are loaded or generated."""
        if not self._keys_initialized:
            # Try to load existing keys
            try:
                await self.client.load_keys("client_keys/private_key.pem", "client_keys/public_key.pem")
                self._keys_initialized = True
            except Exception:
                # Generate new keys if loading fails
                await self.client.generate_keys()
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
        # Extract base_url if provided (OpenAI compatibility)
        base_url = kwargs.pop("base_url", None)
        
        # Extract security_tier if provided
        security_tier = kwargs.pop("security_tier", None)

        # Use the instance's client unless base_url is explicitly overridden
        if base_url is not None:
            # Create a temporary client with overridden base_url
            temp_client = type(self)(base_url=base_url)
            instance = temp_client
        else:
            # Use the instance's existing client
            instance = self

        # Ensure keys are available
        await instance._ensure_keys()

        # Prepare payload in OpenAI format
        payload = {
            "model": model,
            "messages": messages,
            **kwargs
        }

        # Generate a unique payload ID
        payload_id = f"{uuid.uuid4()}"

        # Use instance's api_key if not overridden in kwargs
        request_api_key = kwargs.pop("api_key", instance.api_key)

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
