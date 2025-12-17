import uuid
from typing import Dict, Any, List
from .SecureCompletionClient import SecureCompletionClient

class SecureChatCompletion:
    """
    OpenAI-compatible secure chat completion client.

    This class provides the same interface as OpenAI's ChatCompletion.create()
    method, but automatically encrypts all requests and decrypts all responses
    for secure communication with the NOMYO Router's /v1/chat/secure_completion
    endpoint.

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

    def __init__(self, base_url: str = "https://api.nomyo.ai:12434", allow_http: bool = False):
        """
        Initialize the secure chat completion client.

        Args:
            base_url: Base URL of the NOMYO Router (must use HTTPS for production)
                     This parameter is named 'base_url' for OpenAI compatibility.
            allow_http: Allow HTTP connections (ONLY for local development, never in production)
        """

        self.client = SecureCompletionClient(router_url=base_url, allow_http=allow_http)
        self._keys_initialized = False

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
        payload_id = f"openai-compat-{uuid.uuid4()}"

        # Send secure request
        response = await instance.client.send_secure_request(payload, payload_id)

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
