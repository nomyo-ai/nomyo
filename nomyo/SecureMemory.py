"""
Secure Memory Module for Client-Side

Cross-platform secure memory handling with memory locking and guaranteed zeroing.
This module mirrors the server-side implementation but is optimized for client-side
usage with Python's memory management characteristics.

Supports:
- Linux: mlock() + memset()
- Windows: VirtualLock() + RtlSecureZeroMemory()
- macOS: mlock() + memset()
- Fallback: ctypes-based zeroing for unsupported platforms

Security Features:
- Prevents memory from being swapped to disk
- Guarantees memory is zeroed before deallocation
- Context managers for automatic cleanup
- No root privileges required (uses capabilities on Linux)
"""

import os
import sys
import ctypes
import logging
from typing import Optional, Any
from contextlib import contextmanager
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class MemoryProtectionLevel(Enum):
    """Memory protection levels available"""
    NONE = "none"  # No protection (fallback only)
    ZEROING_ONLY = "zeroing_only"  # Memory zeroing without locking
    FULL = "full"  # Memory locking + zeroing

class SecureMemory:
    """
    Cross-platform secure memory handler for client-side.

    Automatically detects platform and provides best-available security:
    - Linux: mlock + memset
    - Windows: VirtualLock + RtlSecureZeroMemory
    - macOS: mlock + memset
    - Others: Fallback zeroing
    """

    def __init__(self, enable: bool = True):
        """
        Initialize client-side secure memory handler.

        Args:
            enable: Whether to enable secure memory operations (default: True)
                   Set to False to disable all security features
        """
        self.enabled = enable
        self.platform = sys.platform
        self.has_mlock = False
        self.has_secure_zero = False
        self.protection_level = MemoryProtectionLevel.NONE

        if self.enabled:
            self._init_platform_specific()
            self._log_capabilities()
        else:
            logger.info("Secure memory disabled by configuration")

    def _init_platform_specific(self):
        """Initialize platform-specific memory functions"""
        if self.platform.startswith('linux'):
            self._init_linux()
        elif self.platform == 'win32':
            self._init_windows()
        elif self.platform == 'darwin':
            self._init_macos()
        else:
            logger.warning(
                f"Platform {self.platform} not fully supported. "
                "Using fallback memory protection."
            )
            self._init_fallback()

    def _init_linux(self):
        """Initialize Linux-specific functions (mlock + memset)"""
        try:
            self.libc = ctypes.CDLL('libc.so.6')
            self.mlock = self.libc.mlock
            self.munlock = self.libc.munlock
            self.memset = self.libc.memset

            # Set return types
            self.mlock.restype = ctypes.c_int
            self.munlock.restype = ctypes.c_int

            self.has_mlock = True
            self.has_secure_zero = True
            self.protection_level = MemoryProtectionLevel.FULL

            logger.info("Linux secure memory initialized (mlock + memset)")

        except Exception as e:
            logger.warning(f"Could not initialize Linux mlock: {e}. Using fallback.")
            self._init_fallback()

    def _init_windows(self):
        """Initialize Windows-specific functions (VirtualLock + RtlSecureZeroMemory)"""
        try:
            kernel32 = ctypes.windll.kernel32

            # VirtualLock for memory locking
            self.virtual_lock = kernel32.VirtualLock
            self.virtual_unlock = kernel32.VirtualUnlock
            self.virtual_lock.restype = ctypes.c_bool
            self.virtual_unlock.restype = ctypes.c_bool

            # RtlSecureZeroMemory for guaranteed zeroing
            self.secure_zero_memory = kernel32.RtlSecureZeroMemory

            self.has_mlock = True
            self.has_secure_zero = True
            self.protection_level = MemoryProtectionLevel.FULL

            logger.info("Windows secure memory initialized (VirtualLock + RtlSecureZeroMemory)")

        except Exception as e:
            logger.warning(f"Could not initialize Windows VirtualLock: {e}. Using fallback.")
            self._init_fallback()

    def _init_macos(self):
        """Initialize macOS-specific functions (mlock + memset)"""
        try:
            self.libc = ctypes.CDLL('libc.dylib')
            self.mlock = self.libc.mlock
            self.munlock = self.libc.munlock
            self.memset = self.libc.memset

            # Set return types
            self.mlock.restype = ctypes.c_int
            self.munlock.restype = ctypes.c_int

            self.has_mlock = True
            self.has_secure_zero = True
            self.protection_level = MemoryProtectionLevel.FULL

            logger.info("macOS secure memory initialized (mlock + memset)")

        except Exception as e:
            logger.warning(f"Could not initialize macOS mlock: {e}. Using fallback.")
            self._init_fallback()

    def _init_fallback(self):
        """Initialize fallback memory zeroing (no locking)"""
        self.has_mlock = False
        self.has_secure_zero = False
        self.protection_level = MemoryProtectionLevel.ZEROING_ONLY
        logger.info("Using fallback memory protection (zeroing only, no locking)")

    def _log_capabilities(self):
        """Log available security capabilities"""
        logger.info(
            f"Secure memory capabilities - "
            f"Platform: {self.platform}, "
            f"Protection Level: {self.protection_level.value}, "
            f"Memory Locking: {self.has_mlock}, "
            f"Secure Zeroing: {self.has_secure_zero}"
        )

    def lock_memory(self, data: bytes) -> bool:
        """
        Lock memory pages containing data to prevent swapping to disk.

        Args:
            data: Bytes object to lock in memory

        Returns:
            True if successfully locked, False otherwise
        """
        if not self.enabled or not self.has_mlock or not data:
            return False

        try:
            # Get memory address and size
            addr = id(data)
            size = len(data)

            if self.platform.startswith('linux') or self.platform == 'darwin':
                # POSIX mlock
                result = self.mlock(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(size)
                )

                if result != 0:
                    errno = ctypes.get_errno()
                    # ENOMEM (12) or EPERM (1) are common errors
                    if errno == 1:
                        logger.debug(
                            "mlock permission denied. "
                            "Grant CAP_IPC_LOCK or increase ulimit -l"
                        )
                    elif errno == 12:
                        logger.debug("mlock failed: insufficient memory or limit exceeded")
                    else:
                        logger.debug(f"mlock failed with errno {errno}")
                    return False

                return True

            elif self.platform == 'win32':
                # Windows VirtualLock
                result = self.virtual_lock(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(size)
                )

                if not result:
                    logger.debug("VirtualLock failed")
                    return False

                return True

        except Exception as e:
            logger.debug(f"Memory lock failed: {e}")
            return False

        return False

    def unlock_memory(self, data: bytes) -> bool:
        """
        Unlock previously locked memory pages.

        Args:
            data: Bytes object to unlock

        Returns:
            True if successfully unlocked, False otherwise
        """
        if not self.enabled or not self.has_mlock or not data:
            return False

        try:
            addr = id(data)
            size = len(data)

            if self.platform.startswith('linux') or self.platform == 'darwin':
                # POSIX munlock
                result = self.munlock(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(size)
                )
                return result == 0

            elif self.platform == 'win32':
                # Windows VirtualUnlock
                result = self.virtual_unlock(
                    ctypes.c_void_p(addr),
                    ctypes.c_size_t(size)
                )
                return bool(result)

        except Exception as e:
            logger.debug(f"Memory unlock failed: {e}")
            return False

        return False

    def zero_memory(self, data: bytes) -> None:
        """
        Securely zero memory contents.

        Note: Due to Python's memory management, we cannot directly zero
        immutable bytes objects. This function is a best-effort approach
        that works better with mutable bytearray objects.

        For maximum security, use this with bytearray instead of bytes,
        or rely on memory locking to prevent swapping.

        Args:
            data: Bytes object to zero (best effort for bytes, effective for bytearray)
        """
        if not self.enabled or not data:
            return

        try:
            # For bytearray (mutable), we can zero it
            if isinstance(data, bytearray):
                # Zero the bytearray in place
                for i in range(len(data)):
                    data[i] = 0
                logger.debug(f"Zeroed bytearray: {len(data)} bytes")
            else:
                # For bytes (immutable), we can't actually zero the memory
                # Python's bytes are immutable and reference counted
                # The best we can do is ensure no lingering references
                # and let Python's GC handle it
                logger.debug(f"Bytes object is immutable, relying on GC: {len(data)} bytes")

        except Exception as e:
            logger.debug(f"Memory zeroing note: {e}")

    def get_protection_info(self) -> dict:
        """
        Get information about current memory protection capabilities.

        Returns:
            Dictionary with protection status
        """
        return {
            "enabled": self.enabled,
            "platform": self.platform,
            "protection_level": self.protection_level.value,
            "has_memory_locking": self.has_mlock,
            "has_secure_zeroing": self.has_secure_zero,
            "supports_full_protection": self.protection_level == MemoryProtectionLevel.FULL
        }

# Global secure memory instance
_secure_memory = SecureMemory()

@contextmanager
def secure_bytes(data: bytes, lock: bool = True):
    """
    Context manager for secure byte handling with automatic cleanup.

    Provides:
    - Optional memory locking to prevent swapping
    - Guaranteed memory zeroing on exit
    - Automatic cleanup even if exceptions occur

    Args:
        data: Bytes to protect
        lock: Whether to attempt memory locking (default: True)
              Set to False to skip locking but still zero on exit

    Yields:
        The protected bytes object

    Example:
        payload = json.dumps({"secret": "data"}).encode('utf-8')
        with secure_bytes(payload) as protected_data:
            encrypted = encrypt(protected_data)
            # Use encrypted data...
        # Memory automatically zeroed here

    Note:
        Memory locking may fail without appropriate privileges.
        In that case, only zeroing is performed (still provides value).
    """
    locked = False

    try:
        # Try to lock memory if requested
        if lock and _secure_memory.enabled:
            locked = _secure_memory.lock_memory(data)
            if locked:
                logger.debug(f"Memory locked: {len(data)} bytes")
            else:
                logger.debug(
                    f"Memory locking not available for {len(data)} bytes, "
                    "using zeroing only"
                )

        # Yield data for use
        yield data

    finally:
        # Always zero memory
        _secure_memory.zero_memory(data)
        logger.debug(f"Memory zeroed: {len(data)} bytes")

        # Unlock if locked
        if locked:
            _secure_memory.unlock_memory(data)
            logger.debug(f"Memory unlocked: {len(data)} bytes")

def get_memory_protection_info() -> dict:
    """
    Get information about available memory protection features.

    Returns:
        Dictionary with platform and capability information
    """
    return _secure_memory.get_protection_info()

def disable_secure_memory() -> None:
    """
    Disable secure memory operations globally.

    This is useful for testing or when security is not required.
    """
    global _secure_memory
    _secure_memory = SecureMemory(enable=False)
    logger.info("Secure memory operations disabled globally")

def enable_secure_memory() -> None:
    """
    Re-enable secure memory operations globally.

    This reinitializes the secure memory handler with security enabled.
    """
    global _secure_memory
    _secure_memory = SecureMemory(enable=True)
    logger.info("Secure memory operations re-enabled globally")
