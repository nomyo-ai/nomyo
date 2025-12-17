import json, base64, urllib.parse, httpx, os
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureCompletionClient:
    """
    Client for the /v1/chat/secure_completion endpoint.

    Handles:
    - Key generation and management
    - Hybrid encryption/decryption
    - API communication
    - Response parsing
    """

    def __init__(self, router_url: str = "http://api.nomyo.ai:12434"):
        """
        Initialize the secure completion client.

        Args:
            router_url: Base URL of the NOMYO Router (e.g., "http://api.nomyo.ai:12434")
        """
        self.router_url = router_url.rstrip('/')
        self.private_key = None
        self.public_key_pem = None
        self.key_size = 4096  # RSA key size

    async def generate_keys(self, save_to_file: bool = False, key_dir: str = "client_keys", password: Optional[str] = None) -> None:
        """
        Generate RSA key pair for secure communication.

        Args:
            save_to_file: Whether to save keys to files
            key_dir: Directory to save keys (if save_to_file is True)
            password: Optional password to encrypt private key (recommended for production)
        """
        print("🔑 Generating RSA key pair...")

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

        print(f"   ✓ Generated {self.key_size}-bit RSA key pair")

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
                print(f"   ✓ Private key encrypted with password")
            else:
                # Save unencrypted for convenience (not recommended for production)
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                print(f"   ⚠️  Private key saved UNENCRYPTED (not recommended for production)")

            # Write private key with restricted permissions (readable only by owner)
            private_key_path = os.path.join(key_dir, "private_key.pem")
            with open(private_key_path, "wb") as f:
                f.write(private_pem)
            try:
                os.chmod(private_key_path, 0o600)  # Only owner can read/write
                print(f"   ✓ Private key permissions set to 600 (owner-only access)")
            except Exception as e:
                print(f"   ⚠️  Could not set private key permissions: {e}")

            # Save public key (always unencrypted, but with restricted permissions)
            public_key_path = os.path.join(key_dir, "public_key.pem")
            with open(public_key_path, "w") as f:
                f.write(self.public_key_pem)
            try:
                os.chmod(public_key_path, 0o644)  # Owner read/write, group/others read
                print(f"   ✓ Public key permissions set to 644")
            except Exception as e:
                print(f"   ⚠️  Could not set public key permissions: {e}")

            print(f"   ✓ Keys saved to {key_dir}/")

    async def load_keys(self, private_key_path: str, public_key_path: Optional[str] = None, password: Optional[str] = None) -> None:
        """
        Load RSA keys from files.

        Args:
            private_key_path: Path to private key file
            public_key_path: Path to public key file (optional, derived from private key if not provided)
            password: Optional password for encrypted private key
        """
        print(f"🔑 Loading keys from files...")

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
                print(f"   ✓ Private key loaded {'with password' if pwd else 'without password'}")
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

        print("   ✓ Keys loaded successfully")

    async def fetch_server_public_key(self) -> str:
        """
        Fetch the server's public key from the /pki/public_key endpoint.

        Returns:
            Server's public key as PEM string
        """
        print("🔑 Fetching server's public key...")

        url = f"{self.router_url}/pki/public_key"
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    server_public_key = response.text
                    print("   ✓ Server's public key fetched successfully")
                    return server_public_key
                else:
                    raise ValueError(f"Failed to fetch server's public key: HTTP {response.status_code}")
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
            Exception: If encryption fails
        """
        print("🔒 Encrypting payload...")

        try:
            # Serialize payload to JSON
            payload_json = json.dumps(payload).encode('utf-8')
            print(f"   Payload size: {len(payload_json)} bytes")

            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key

            # Encrypt payload with AES-GCM using Cipher API (matching server implementation)
            nonce = os.urandom(12)  # 96-bit nonce for GCM
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
            print(f"   ✓ Encrypted package size: {len(package_json)} bytes")

            return package_json

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    async def decrypt_response(self, encrypted_response: bytes, payload_id: str) -> Dict[str, Any]:
        """
        Decrypt a response from the secure endpoint.

        Args:
            encrypted_response: Encrypted response bytes
            payload_id: Payload ID for metadata verification

        Returns:
            Decrypted response dictionary
        """
        print("🔓 Decrypting response...")

        # Parse encrypted package
        try:
            package = json.loads(encrypted_response.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid encrypted package format: {e}")

        # Validate package structure
        required_fields = ["version", "algorithm", "encrypted_payload", "encrypted_aes_key"]
        for field in required_fields:
            if field not in package:
                raise ValueError(f"Missing required field in encrypted package: {field}")

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

        # Add metadata for debugging
        if "_metadata" not in response:
            response["_metadata"] = {}
        response["_metadata"].update({
            "payload_id": payload_id,
            "processed_at": package.get("processed_at"),
            "is_encrypted": True,
            "encryption_algorithm": package["algorithm"]
        })

        print(f"   ✓ Response decrypted successfully")
        print(f"   Response size: {len(plaintext)} bytes")

        return response

    async def send_secure_request(self, payload: Dict[str, Any], payload_id: str) -> Dict[str, Any]:
        """
        Send a secure chat completion request to the router.

        Args:
            payload: Chat completion request payload
            payload_id: Unique identifier for this request

        Returns:
            Decrypted response from the LLM
        """
        print("\n📤 Sending secure chat completion request...")

        # Step 1: Encrypt the payload
        encrypted_payload = await self.encrypt_payload(payload)

        # Step 2: Prepare headers
        headers = {
            "X-Payload-ID": payload_id,
            "X-Public-Key": urllib.parse.quote(self.public_key_pem),
            "Content-Type": "application/octet-stream"
        }

        # Step 3: Send request to router
        url = f"{self.router_url}/v1/chat/secure_completion"
        print(f"   Target URL: {url}")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    url,
                    headers=headers,
                    content=encrypted_payload
                )

                print(f"   HTTP Status: {response.status_code}")

                if response.status_code == 200:
                    # Step 4: Decrypt the response
                    encrypted_response = response.content
                    decrypted_response = await self.decrypt_response(encrypted_response, payload_id)
                    return decrypted_response

                elif response.status_code == 400:
                    error = response.json()
                    raise ValueError(f"Bad request: {error.get('detail', 'Unknown error')}")

                elif response.status_code == 404:
                    error = response.json()
                    raise ValueError(f"Endpoint not found: {error.get('detail', 'Secure inference not enabled')}")

                elif response.status_code == 500:
                    error = response.json()
                    raise ValueError(f"Server error: {error.get('detail', 'Internal server error')}")

                else:
                    raise ValueError(f"Unexpected status code: {response.status_code}")

        except httpx.NetworkError as e:
            raise ConnectionError(f"Failed to connect to router: {e}")
        except Exception as e:
            raise Exception(f"Request failed: {e}")
