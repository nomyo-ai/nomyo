import json, base64, urllib.parse, httpx, os, secrets, warnings, logging
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Setup module logger
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass

class APIError(Exception):
    """Base class for all API-related errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, error_details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.status_code = status_code
        self.error_details = error_details
        super().__init__(message)

    def __str__(self):
        return self.message

class AuthenticationError(APIError):
    """Raised when authentication fails (e.g., invalid API key)."""
    def __init__(self, message: str, status_code: int = 401, error_details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code, error_details)

class InvalidRequestError(APIError):
    """Raised when the request is invalid (HTTP 400)."""
    def __init__(self, message: str, status_code: int = 400, error_details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code, error_details)

class APIConnectionError(Exception):
    """Raised when there's a connection error."""
    pass

class RateLimitError(APIError):
    """Raised when rate limit is exceeded (HTTP 429)."""
    def __init__(self, message: str, status_code: int = 429, error_details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code, error_details)

class ServerError(APIError):
    """Raised when the server returns an error (HTTP 500)."""
    def __init__(self, message: str, status_code: int = 500, error_details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code, error_details)

class SecureCompletionClient:
    """
    Client for the /v1/chat/secure_completion endpoint.

    Handles:
    - Key generation and management
    - Hybrid encryption/decryption
    - API communication
    - Response parsing
    """

    def __init__(self, router_url: str = "https://api.nomyo.ai:12434", allow_http: bool = False):
        """
        Initialize the secure completion client.

        Args:
            router_url: Base URL of the NOMYO Router (must use HTTPS for production)
            allow_http: Allow HTTP connections (ONLY for local development, never in production)
        """
        self.router_url = router_url.rstrip('/')
        self.private_key = None
        self.public_key_pem = None
        self.key_size = 4096  # RSA key size
        self.allow_http = allow_http  # Store for use in fetch_server_public_key

        # Validate HTTPS for security
        if not self.router_url.startswith("https://"):
            if not allow_http:
                warnings.warn(
                    "⚠️  WARNING: Using HTTP instead of HTTPS. "
                    "This is INSECURE and should only be used for local development. "
                    "Man-in-the-middle attacks are possible!",
                    UserWarning,
                    stacklevel=2
                )
            else:
                logger.warning("HTTP mode enabled for local development (INSECURE)")

    async def generate_keys(self, save_to_file: bool = False, key_dir: str = "client_keys", password: Optional[str] = None) -> None:
        """
        Generate RSA key pair for secure communication.

        Args:
            save_to_file: Whether to save keys to files
            key_dir: Directory to save keys (if save_to_file is True)
            password: Optional password to encrypt private key (recommended for production)
        """
        logger.info("Generating RSA key pair...")

        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        # Get public key
        public_key = self.private_key.public_key()

        # Serialize public key to PEM format
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        logger.debug("Generated %d-bit RSA key pair", self.key_size)

        if save_to_file:
            os.makedirs(key_dir, exist_ok=True)

            # Save private key
            if password:
                # Encrypt private key with user-provided password
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
                )
                logger.debug("Private key encrypted with password")
            else:
                # Save unencrypted for convenience (not recommended for production)
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                logger.warning("Private key saved UNENCRYPTED (not recommended for production)")

            # Write private key with restricted permissions (readable only by owner)
            private_key_path = os.path.join(key_dir, "private_key.pem")
            with open(private_key_path, "wb") as f:
                f.write(private_pem)
            try:
                os.chmod(private_key_path, 0o600)  # Only owner can read/write
                logger.debug("Private key permissions set to 600 (owner-only access)")
            except Exception as e:
                logger.warning("Could not set private key permissions: %s", e)

            # Save public key (always unencrypted, but with restricted permissions)
            public_key_path = os.path.join(key_dir, "public_key.pem")
            with open(public_key_path, "w") as f:
                f.write(self.public_key_pem)
            try:
                os.chmod(public_key_path, 0o644)  # Owner read/write, group/others read
                logger.debug("Public key permissions set to 644")
            except Exception as e:
                logger.warning("Could not set public key permissions: %s", e)

            logger.debug("Keys saved to %s/", key_dir)

    async def load_keys(self, private_key_path: str, public_key_path: Optional[str] = None, password: Optional[str] = None) -> None:
        """
        Load RSA keys from files.

        Args:
            private_key_path: Path to private key file
            public_key_path: Path to public key file (optional, derived from private key if not provided)
            password: Optional password for encrypted private key
        """
        logger.info("Loading keys from files...")

        # Load private key
        with open(private_key_path, "rb") as f:
            private_pem = f.read()

        # Try different password options
        password_options = []
        if password:
            password_options.append(password.encode('utf-8'))
        password_options.append(None)  # Try without password

        last_error = None
        for pwd in password_options:
            try:
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=pwd,
                    backend=default_backend()
                )
                logger.debug("Private key loaded %s", 'with password' if pwd else 'without password')
                break
            except Exception as e:
                last_error = e
                continue
        else:
            raise ValueError(f"Failed to load private key. Tried all password options. Error: {last_error}")

        # Get public key
        public_key = self.private_key.public_key()

        # Load public key from file if provided, otherwise derive from private key
        if public_key_path:
            with open(public_key_path, "r") as f:
                self.public_key_pem = f.read().strip()
        else:
            self.public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

        # Validate loaded key
        self._validate_rsa_key(self.private_key, "private")

        logger.debug("Keys loaded successfully")

    async def fetch_server_public_key(self) -> str:
        """
        Fetch the server's public key from the /pki/public_key endpoint.

        Uses HTTPS with certificate verification to prevent MITM attacks.
        HTTP is only allowed if explicitly enabled via allow_http parameter.

        Returns:
            Server's public key as PEM string

        Raises:
            SecurityError: If HTTPS is not used and HTTP is not explicitly allowed
            ConnectionError: If connection fails
            ValueError: If response is invalid
        """
        logger.info("Fetching server's public key...")

        # Security check: Ensure HTTPS is used unless HTTP explicitly allowed
        if not self.router_url.startswith("https://"):
            if not self.allow_http:
                raise SecurityError(
                    "Server public key must be fetched over HTTPS to prevent MITM attacks. "
                    "For local development, initialize with allow_http=True: "
                    "SecureChatCompletion(base_url='http://localhost:12434', allow_http=True)"
                )
            else:
                logger.warning("Fetching key over HTTP (local development mode)")

        url = f"{self.router_url}/pki/public_key"

        try:
            # Use HTTPS verification only for HTTPS URLs
            verify_ssl = self.router_url.startswith("https://")

            async with httpx.AsyncClient(
                timeout=60.0,
                verify=verify_ssl,  # Verify SSL/TLS certificates for HTTPS
            ) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    server_public_key = response.text

                    # Validate it's a valid PEM key
                    try:
                        serialization.load_pem_public_key(
                            server_public_key.encode('utf-8'),
                            backend=default_backend()
                        )
                    except Exception:
                        raise ValueError("Server returned invalid public key format")

                    if verify_ssl:
                        logger.debug("Server's public key fetched securely over HTTPS")
                    else:
                        logger.warning("Server's public key fetched over HTTP (INSECURE)")
                    return server_public_key
                else:
                    raise ValueError(f"Failed to fetch server's public key: HTTP {response.status_code}")

        except httpx.ConnectError as e:
            raise ConnectionError(f"Failed to connect to server: {e}")
        except httpx.TimeoutException:
            raise ConnectionError("Connection to server timed out")
        except SecurityError:
            raise  # Re-raise security errors
        except ValueError:
            raise  # Re-raise validation errors
        except Exception as e:
            raise ValueError(f"Failed to fetch server's public key: {e}")

    async def encrypt_payload(self, payload: Dict[str, Any]) -> bytes:
        """
        Encrypt a payload using hybrid encryption (AES-256-GCM + RSA-OAEP).

        Args:
            payload: Dictionary containing the chat completion request

        Returns:
            Encrypted payload as bytes

        Raises:
            ValueError: If payload is invalid or too large
            SecurityError: If encryption fails
        """
        logger.info("Encrypting payload...")

        # Validate payload
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary")

        if not payload:
            raise ValueError("Payload cannot be empty")

        try:
            # Serialize payload to JSON
            payload_json = json.dumps(payload).encode('utf-8')

            # Validate payload size (prevent DoS)
            MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10MB limit
            if len(payload_json) > MAX_PAYLOAD_SIZE:
                raise ValueError(f"Payload too large: {len(payload_json)} bytes (max: {MAX_PAYLOAD_SIZE})")

            logger.debug("Payload size: %d bytes", len(payload_json))

            # Generate cryptographically secure random AES key
            aes_key = secrets.token_bytes(32)  # 256-bit key

            # Encrypt payload with AES-GCM using Cipher API (matching server implementation)
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(payload_json) + encryptor.finalize()
            tag = encryptor.tag

            # Fetch server's public key for encrypting the AES key
            server_public_key_pem = await self.fetch_server_public_key()

            # Encrypt AES key with server's RSA-OAEP
            server_public_key = serialization.load_pem_public_key(
                server_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            encrypted_aes_key = server_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Create encrypted package
            encrypted_package = {
                "version": "1.0",
                "algorithm": "hybrid-aes256-rsa4096",
                "encrypted_payload": {
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "tag": base64.b64encode(tag).decode('utf-8')
                },
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
                "key_algorithm": "RSA-OAEP-SHA256",
                "payload_algorithm": "AES-256-GCM"
            }

            # Serialize package to JSON and return as bytes
            package_json = json.dumps(encrypted_package).encode('utf-8')
            logger.debug("Encrypted package size: %d bytes", len(package_json))

            return package_json

        except ValueError:
            raise  # Re-raise validation errors
        except SecurityError:
            raise  # Re-raise security errors
        except Exception as e:
            # Don't leak internal details
            raise SecurityError("Encryption operation failed")

    async def decrypt_response(self, encrypted_response: bytes, payload_id: str) -> Dict[str, Any]:
        """
        Decrypt a response from the secure endpoint.

        Args:
            encrypted_response: Encrypted response bytes
            payload_id: Payload ID for metadata verification

        Returns:
            Decrypted response dictionary

        Raises:
            ValueError: If response format is invalid
            SecurityError: If decryption fails or integrity check fails
        """
        logger.info("Decrypting response...")

        # Validate input
        if not encrypted_response:
            raise ValueError("Empty encrypted response")

        if not isinstance(encrypted_response, bytes):
            raise ValueError("Encrypted response must be bytes")

        # Parse encrypted package
        try:
            package = json.loads(encrypted_response.decode('utf-8'))
        except json.JSONDecodeError:
            raise ValueError("Invalid encrypted package format: malformed JSON")
        except UnicodeDecodeError:
            raise ValueError("Invalid encrypted package format: not valid UTF-8")

        # Validate package structure
        required_fields = ["version", "algorithm", "encrypted_payload", "encrypted_aes_key"]
        missing_fields = [f for f in required_fields if f not in package]
        if missing_fields:
            raise ValueError(f"Missing required fields in encrypted package: {', '.join(missing_fields)}")

        # Validate encrypted_payload structure
        if not isinstance(package["encrypted_payload"], dict):
            raise ValueError("Invalid encrypted_payload: must be a dictionary")

        payload_required = ["ciphertext", "nonce", "tag"]
        missing_payload_fields = [f for f in payload_required if f not in package["encrypted_payload"]]
        if missing_payload_fields:
            raise ValueError(f"Missing fields in encrypted_payload: {', '.join(missing_payload_fields)}")

        # Decrypt with proper error handling
        try:
            # Decrypt AES key with private key
            encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"])
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt payload with AES-GCM using Cipher API (matching server implementation)
            ciphertext = base64.b64decode(package["encrypted_payload"]["ciphertext"])
            nonce = base64.b64decode(package["encrypted_payload"]["nonce"])
            tag = base64.b64decode(package["encrypted_payload"]["tag"])

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # Parse decrypted response
            response = json.loads(plaintext.decode('utf-8'))
        except Exception:
            # Don't leak specific decryption errors (timing attacks)
            raise SecurityError("Decryption failed: integrity check or authentication failed")

        # Add metadata for debugging
        if "_metadata" not in response:
            response["_metadata"] = {}
        response["_metadata"].update({
            "payload_id": payload_id,
            "processed_at": package.get("processed_at"),
            "is_encrypted": True,
            "encryption_algorithm": package["algorithm"]
        })

        logger.debug("Response decrypted successfully")
        logger.debug("Response size: %d bytes", len(plaintext))

        return response

    async def send_secure_request(self, payload: Dict[str, Any], payload_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a secure chat completion request to the router.

        Args:
            payload: Chat completion request payload
            payload_id: Unique identifier for this request
            api_key: Optional API key for bearer authentication

        Returns:
            Decrypted response from the LLM

        Raises:
            AuthenticationError: If API key is invalid or missing (HTTP 401)
            InvalidRequestError: If the request is invalid (HTTP 400)
            APIError: For other HTTP errors
            APIConnectionError: If connection fails
            SecurityError: If encryption/decryption fails
        """
        logger.info("Sending secure chat completion request...")

        # Step 1: Encrypt the payload
        encrypted_payload = await self.encrypt_payload(payload)

        # Step 2: Prepare headers
        headers = {
            "X-Payload-ID": payload_id,
            "X-Public-Key": urllib.parse.quote(self.public_key_pem),
            "Content-Type": "application/octet-stream"
        }

        # Add Authorization header if api_key is provided
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Step 3: Send request to router
        url = f"{self.router_url}/v1/chat/secure_completion"
        logger.debug("Target URL: %s", url)

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    url,
                    headers=headers,
                    content=encrypted_payload
                )

                logger.debug("HTTP Status: %d", response.status_code)

                if response.status_code == 200:
                    # Step 4: Decrypt the response
                    encrypted_response = response.content
                    decrypted_response = await self.decrypt_response(encrypted_response, payload_id)
                    return decrypted_response

                elif response.status_code == 400:
                    # Bad request
                    try:
                        error = response.json()
                        raise InvalidRequestError(
                            f"Bad request: {error.get('detail', 'Unknown error')}",
                            status_code=400,
                            error_details=error
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise InvalidRequestError("Bad request: Invalid response format")

                elif response.status_code == 401:
                    # Unauthorized - authentication failed
                    try:
                        error = response.json()
                        error_message = error.get('detail', 'Invalid API key or authentication failed')
                        raise AuthenticationError(
                            error_message,
                            status_code=401,
                            error_details=error
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise AuthenticationError("Invalid API key or authentication failed")

                elif response.status_code == 404:
                    # Endpoint not found
                    try:
                        error = response.json()
                        raise APIError(
                            f"Endpoint not found: {error.get('detail', 'Secure inference not enabled')}",
                            status_code=404,
                            error_details=error
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise APIError("Endpoint not found: Secure inference not enabled")

                elif response.status_code == 429:
                    # Rate limit exceeded
                    try:
                        error = response.json()
                        raise RateLimitError(
                            f"Rate limit exceeded: {error.get('detail', 'Too many requests')}",
                            status_code=429,
                            error_details=error
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise RateLimitError("Rate limit exceeded: Too many requests")

                elif response.status_code == 500:
                    # Server error
                    try:
                        error = response.json()
                        raise ServerError(
                            f"Server error: {error.get('detail', 'Internal server error')}",
                            status_code=500,
                            error_details=error
                        )
                    except (json.JSONDecodeError, ValueError):
                        raise ServerError("Server error: Internal server error")

                else:
                    # Unexpected status code
                    raise APIError(
                        f"Unexpected status code: {response.status_code}",
                        status_code=response.status_code
                    )

        except httpx.NetworkError as e:
            raise APIConnectionError(f"Failed to connect to router: {e}")
        except (SecurityError, APIError, AuthenticationError, InvalidRequestError, RateLimitError, ServerError, APIConnectionError):
            raise  # Re-raise known exceptions
        except Exception as e:
            raise Exception(f"Request failed: {e}")

    def _validate_rsa_key(self, key, key_type: str = "private") -> None:
        """
        Validate that a key is a valid RSA key with appropriate size.

        Args:
            key: The key to validate
            key_type: "private" or "public"

        Raises:
            ValueError: If key is invalid
        """
        if key_type == "private":
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("Invalid private key: not an RSA private key")
            key_size = key.key_size
        else:
            if not isinstance(key, rsa.RSAPublicKey):
                raise ValueError("Invalid public key: not an RSA public key")
            key_size = key.key_size

        MIN_KEY_SIZE = 2048
        if key_size < MIN_KEY_SIZE:
            raise ValueError(
                f"Key size {key_size} is too small. "
                f"Minimum recommended size is {MIN_KEY_SIZE} bits."
            )

        logger.debug("Valid %d-bit RSA %s key", key_size, key_type)
