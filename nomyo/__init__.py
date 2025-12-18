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

__all__ = [
    'SecureChatCompletion',
    'APIError',
    'AuthenticationError',
    'InvalidRequestError',
    'APIConnectionError',
    'RateLimitError',
    'ServerError'
]

__version__ = "0.1.0"
__author__ = "NOMYO AI"
__license__ = "Apache-2.0"
__all__ = ["SecureChatCompletion"]
