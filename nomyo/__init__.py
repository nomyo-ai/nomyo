"""
NOMYO Secure Python Chat Client

OpenAI-compatible secure chat client with end-to-end encryption.
"""

from .nomyo import SecureChatCompletion
from .SecureCompletionClient import (
    APIError,
    AuthenticationError,
    InvalidRequestError,
    APIConnectionError,
    RateLimitError,
    ServerError
)

# Import secure memory module if available
try:
    from .SecureMemory import (
        get_memory_protection_info,
        disable_secure_memory,
        enable_secure_memory,
        secure_bytearray,
        secure_bytes,  # Deprecated, use secure_bytearray instead
        SecureBuffer
    )
except ImportError:
    pass

__all__ = [
    'SecureChatCompletion',
    'APIError',
    'AuthenticationError',
    'InvalidRequestError',
    'APIConnectionError',
    'RateLimitError',
    'ServerError',
    'get_memory_protection_info',
    'disable_secure_memory',
    'enable_secure_memory',
    'secure_bytearray',
    'secure_bytes',  # Deprecated, use secure_bytearray instead
    'SecureBuffer'
]

__version__ = "0.1.0"
__author__ = "NOMYO AI"
__license__ = "Apache-2.0"
