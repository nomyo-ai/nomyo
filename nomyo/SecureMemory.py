"""
Secure Memory Module for Client-Side

Cross-platform secure memory handling with memory locking and guaranteed zeroing.
This module mirrors the server-side implementation but is optimized for client-side
usage with Python's memory management characteristics.

Supports:
- Linux: mlock() + memset()
- Windows: VirtualLock() + RtlZeroMemory()
- macOS: mlock() + memset()
- Fallback: ctypes-based zeroing for unsupported platforms

Security Features:
- Prevents memory from being swapped to disk
- Guarantees memory is zeroed before deallocation
- Context managers for automatic cleanup
- No root privileges required (uses capabilities on Linux)

IMPORTANT: This module works with mutable bytearray objects for true security.
Python's immutable bytes objects cannot be securely zeroed in place.
"""

import ctypes
import logging
import sys
from contextlib import contextmanager
from enum import Enum
from typing import Optional, Union

# Configure logging
logger = logging.getLogger(__name__)


class MemoryProtectionLevel(Enum):
    """Memory protection levels available"""
    NONE = "none"  # No protection (fallback only)
    ZEROING_ONLY = "zeroing_only"  # Memory zeroing without locking
    FULL = "full"  # Memory locking + zeroing


class SecureBuffer:
    """
    A secure buffer that wraps a bytearray with proper memory protection.

    This class provides:
    - Correct memory address calculation using ctypes
    - Platform-specific memory locking
    - Guaranteed secure zeroing on cleanup
    - Context manager support for automatic cleanup

    Usage:
        with SecureBuffer(secret_data) as buf:
            # Use buf.data (bytearray) for operations
            process(buf.data)
        # Memory is securely zeroed here
    """

    def __init__(self, data: Union[bytes, bytearray], secure_memory: 'SecureMemory'):
        """
        Initialize a secure buffer.

        Args:
            data: Initial data (will be copied into a mutable bytearray)
            secure_memory: SecureMemory instance for platform operations
        """
        self._secure_memory = secure_memory
        self._locked = False
        self._size = len(data)

        # Create mutable bytearray and ctypes buffer for proper address handling
        self._data = bytearray(data)
        self._ctypes_buffer = (ctypes.c_char * self._size).from_buffer(self._data)
        self._address = ctypes.addressof(self._ctypes_buffer)

        # Zero the original if it was a bytearray (caller's copy)
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

    @property
    def data(self) -> bytearray:
        """Get the underlying bytearray data."""
        return self._data

    @property
    def address(self) -> int:
        """Get the memory address of the buffer."""
        return self._address

    @property
    def size(self) -> int:
        """Get the size of the buffer."""
        return self._size

    def lock(self) -> bool:
        """Lock the buffer memory to prevent swapping."""
        if self._locked or not self._secure_memory.enabled:
            return self._locked

        self._locked = self._secure_memory._lock_memory_at(self._address, self._size)
        return self._locked

    def unlock(self) -> bool:
        """Unlock the buffer memory."""
        if not self._locked:
            return True

        result = self._secure_memory._unlock_memory_at(self._address, self._size)
        if result:
            self._locked = False
        return result

    def zero(self) -> None:
        """Securely zero the buffer contents."""
        self._secure_memory._zero_memory_at(self._address, self._size)
        # Also zero the Python bytearray for defense in depth
        for i in range(len(self._data)):
            self._data[i] = 0

    def __enter__(self) -> 'SecureBuffer':
        self.lock()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.zero()
        self.unlock()

    def __len__(self) -> int:
        return self._size

    def __bytes__(self) -> bytes:
        """Convert to bytes (creates a copy - use with caution)."""
        return bytes(self._data)


class SecureMemory:
    """
    Cross-platform secure memory handler for client-side.

    Automatically detects platform and provides best-available security:
    - Linux: mlock + memset
    - Windows: VirtualLock + RtlZeroMemory
    - macOS: mlock + memset
    - Others: Fallback zeroing

    IMPORTANT: For true security, use SecureBuffer or secure_bytearray() context
    manager with bytearray objects. Python's immutable bytes cannot be securely
    zeroed in place.
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
        self._page_size = 4096  # Default, will be updated per platform

        # Platform-specific function references
        self._mlock_func = None
        self._munlock_func = None
        self._memset_func = None
        self._libc = None

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
            # Use use_errno=True for proper errno handling
            self._libc = ctypes.CDLL('libc.so.6', use_errno=True)

            # Get page size
            try:
                self._page_size = self._libc.getpagesize()
            except Exception:
                self._page_size = 4096

            # Setup mlock/munlock
            self._mlock_func = self._libc.mlock
            self._mlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._mlock_func.restype = ctypes.c_int

            self._munlock_func = self._libc.munlock
            self._munlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._munlock_func.restype = ctypes.c_int

            # Setup memset for secure zeroing
            self._memset_func = self._libc.memset
            self._memset_func.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            self._memset_func.restype = ctypes.c_void_p

            self.has_mlock = True
            self.has_secure_zero = True
            self.protection_level = MemoryProtectionLevel.FULL

            logger.info("Linux secure memory initialized (mlock + memset)")

        except Exception as e:
            logger.warning(f"Could not initialize Linux mlock: {e}. Using fallback.")
            self._init_fallback()

    def _init_windows(self):
        """Initialize Windows-specific functions (VirtualLock + RtlZeroMemory)"""
        try:
            kernel32 = ctypes.windll.kernel32

            # Get page size
            class SYSTEM_INFO(ctypes.Structure):
                _fields_ = [
                    ("wProcessorArchitecture", ctypes.c_ushort),
                    ("wReserved", ctypes.c_ushort),
                    ("dwPageSize", ctypes.c_ulong),
                    ("lpMinimumApplicationAddress", ctypes.c_void_p),
                    ("lpMaximumApplicationAddress", ctypes.c_void_p),
                    ("dwActiveProcessorMask", ctypes.c_void_p),
                    ("dwNumberOfProcessors", ctypes.c_ulong),
                    ("dwProcessorType", ctypes.c_ulong),
                    ("dwAllocationGranularity", ctypes.c_ulong),
                    ("wProcessorLevel", ctypes.c_ushort),
                    ("wProcessorRevision", ctypes.c_ushort),
                ]

            try:
                sysinfo = SYSTEM_INFO()
                kernel32.GetSystemInfo(ctypes.byref(sysinfo))
                self._page_size = sysinfo.dwPageSize
            except Exception:
                self._page_size = 4096

            # VirtualLock for memory locking
            self._mlock_func = kernel32.VirtualLock
            self._mlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._mlock_func.restype = ctypes.c_bool

            self._munlock_func = kernel32.VirtualUnlock
            self._munlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._munlock_func.restype = ctypes.c_bool

            # RtlZeroMemory from ntdll (not RtlSecureZeroMemory which is a macro)
            # Note: RtlZeroMemory may be optimized away by compiler, but it's the
            # best we can do from Python. For true secure zeroing, we also
            # implement a Python-level volatile write pattern.
            try:
                ntdll = ctypes.windll.ntdll
                self._memset_func = ntdll.RtlZeroMemory
                self._memset_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self._memset_func.restype = None
                self._windows_zero_is_rtlzero = True
            except Exception:
                # Fallback to kernel32.RtlZeroMemory if available
                try:
                    self._memset_func = kernel32.RtlZeroMemory
                    self._memset_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    self._memset_func.restype = None
                    self._windows_zero_is_rtlzero = True
                except Exception:
                    self._memset_func = None
                    self._windows_zero_is_rtlzero = False
                    logger.warning("RtlZeroMemory not available, using Python zeroing")

            self.has_mlock = True
            self.has_secure_zero = True  # We have fallback even if RtlZeroMemory fails
            self.protection_level = MemoryProtectionLevel.FULL

            logger.info("Windows secure memory initialized (VirtualLock + RtlZeroMemory)")

        except Exception as e:
            logger.warning(f"Could not initialize Windows VirtualLock: {e}. Using fallback.")
            self._init_fallback()

    def _init_macos(self):
        """Initialize macOS-specific functions (mlock + memset)"""
        try:
            # Use use_errno=True for proper errno handling
            self._libc = ctypes.CDLL('libc.dylib', use_errno=True)

            # Get page size
            try:
                self._page_size = self._libc.getpagesize()
            except Exception:
                self._page_size = 4096

            # Setup mlock/munlock
            self._mlock_func = self._libc.mlock
            self._mlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._mlock_func.restype = ctypes.c_int

            self._munlock_func = self._libc.munlock
            self._munlock_func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._munlock_func.restype = ctypes.c_int

            # Setup memset for secure zeroing
            self._memset_func = self._libc.memset
            self._memset_func.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            self._memset_func.restype = ctypes.c_void_p

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
        self.has_secure_zero = True  # We can still zero memory at Python level
        self.protection_level = MemoryProtectionLevel.ZEROING_ONLY
        self._mlock_func = None
        self._munlock_func = None
        self._memset_func = None
        logger.info("Using fallback memory protection (zeroing only, no locking)")

    def _log_capabilities(self):
        """Log available security capabilities"""
        logger.info(
            f"Secure memory capabilities - "
            f"Platform: {self.platform}, "
            f"Protection Level: {self.protection_level.value}, "
            f"Memory Locking: {self.has_mlock}, "
            f"Secure Zeroing: {self.has_secure_zero}, "
            f"Page Size: {self._page_size}"
        )

    def _get_page_aligned_range(self, addr: int, size: int) -> tuple:
        """
        Calculate page-aligned address and size for mlock operations.

        Args:
            addr: Memory address
            size: Size in bytes

        Returns:
            Tuple of (aligned_addr, aligned_size)
        """
        page_mask = self._page_size - 1
        aligned_addr = addr & ~page_mask
        end_addr = addr + size
        aligned_end = (end_addr + page_mask) & ~page_mask
        aligned_size = aligned_end - aligned_addr
        return aligned_addr, aligned_size

    def _lock_memory_at(self, addr: int, size: int) -> bool:
        """
        Lock memory at a specific address.

        Args:
            addr: Memory address (will be page-aligned)
            size: Size in bytes

        Returns:
            True if successfully locked, False otherwise
        """
        if not self.enabled or not self.has_mlock or not self._mlock_func:
            return False

        try:
            # Page-align the address and size
            aligned_addr, aligned_size = self._get_page_aligned_range(addr, size)

            if self.platform.startswith('linux') or self.platform == 'darwin':
                result = self._mlock_func(
                    ctypes.c_void_p(aligned_addr),
                    ctypes.c_size_t(aligned_size)
                )

                if result != 0:
                    errno = ctypes.get_errno()
                    if errno == 1:  # EPERM
                        logger.debug(
                            "mlock permission denied. "
                            "Grant CAP_IPC_LOCK or increase ulimit -l"
                        )
                    elif errno == 12:  # ENOMEM
                        logger.debug("mlock failed: insufficient memory or limit exceeded")
                    else:
                        logger.debug(f"mlock failed with errno {errno}")
                    return False

                logger.debug(f"Memory locked: {size} bytes at 0x{addr:x}")
                return True

            elif self.platform == 'win32':
                result = self._mlock_func(
                    ctypes.c_void_p(aligned_addr),
                    ctypes.c_size_t(aligned_size)
                )

                if not result:
                    error = ctypes.get_last_error()
                    logger.debug(f"VirtualLock failed with error {error}")
                    return False

                logger.debug(f"Memory locked: {size} bytes at 0x{addr:x}")
                return True

        except Exception as e:
            logger.debug(f"Memory lock failed: {e}")
            return False

        return False

    def _unlock_memory_at(self, addr: int, size: int) -> bool:
        """
        Unlock memory at a specific address.

        Args:
            addr: Memory address (will be page-aligned)
            size: Size in bytes

        Returns:
            True if successfully unlocked, False otherwise
        """
        if not self.enabled or not self.has_mlock or not self._munlock_func:
            return False

        try:
            # Page-align the address and size
            aligned_addr, aligned_size = self._get_page_aligned_range(addr, size)

            if self.platform.startswith('linux') or self.platform == 'darwin':
                result = self._munlock_func(
                    ctypes.c_void_p(aligned_addr),
                    ctypes.c_size_t(aligned_size)
                )
                success = result == 0
                if success:
                    logger.debug(f"Memory unlocked: {size} bytes at 0x{addr:x}")
                return success

            elif self.platform == 'win32':
                result = self._munlock_func(
                    ctypes.c_void_p(aligned_addr),
                    ctypes.c_size_t(aligned_size)
                )
                if result:
                    logger.debug(f"Memory unlocked: {size} bytes at 0x{addr:x}")
                return bool(result)

        except Exception as e:
            logger.debug(f"Memory unlock failed: {e}")
            return False

        return False

    def _zero_memory_at(self, addr: int, size: int) -> None:
        """
        Securely zero memory at a specific address.

        Uses platform-specific functions when available, with Python fallback.

        Args:
            addr: Memory address
            size: Size in bytes
        """
        if not self.enabled or size == 0:
            return

        try:
            if self._memset_func is not None:
                if self.platform.startswith('linux') or self.platform == 'darwin':
                    # memset(addr, 0, size)
                    self._memset_func(
                        ctypes.c_void_p(addr),
                        ctypes.c_int(0),
                        ctypes.c_size_t(size)
                    )
                elif self.platform == 'win32' and hasattr(self, '_windows_zero_is_rtlzero'):
                    # RtlZeroMemory(addr, size)
                    self._memset_func(
                        ctypes.c_void_p(addr),
                        ctypes.c_size_t(size)
                    )
                logger.debug(f"Memory zeroed (native): {size} bytes at 0x{addr:x}")
            else:
                # Fallback: zero via ctypes byte-by-byte
                # This is slower but works everywhere
                char_array = (ctypes.c_char * size).from_address(addr)
                for i in range(size):
                    char_array[i] = b'\x00'
                logger.debug(f"Memory zeroed (fallback): {size} bytes at 0x{addr:x}")

        except Exception as e:
            logger.warning(f"Memory zeroing failed: {e}")
            # Last resort: try to zero via ctypes
            try:
                char_array = (ctypes.c_char * size).from_address(addr)
                for i in range(size):
                    char_array[i] = b'\x00'
            except Exception:
                pass

    def create_secure_buffer(self, data: Union[bytes, bytearray]) -> SecureBuffer:
        """
        Create a SecureBuffer from data.

        This is the recommended way to handle sensitive data.

        Args:
            data: Data to protect (will be copied, original should be discarded)

        Returns:
            SecureBuffer instance
        """
        return SecureBuffer(data, self)

    def lock_memory(self, data: bytearray) -> bool:
        """
        Lock memory containing a bytearray to prevent swapping.

        IMPORTANT: Only works reliably with bytearray objects.
        Use create_secure_buffer() for better security guarantees.

        Args:
            data: Bytearray to lock in memory

        Returns:
            True if successfully locked, False otherwise
        """
        if not isinstance(data, bytearray):
            logger.warning(
                "lock_memory() called with non-bytearray. "
                "Use create_secure_buffer() for bytes objects."
            )
            return False

        if not self.enabled or not self.has_mlock or not data:
            return False

        try:
            # Create ctypes buffer to get correct address
            ctypes_buffer = (ctypes.c_char * len(data)).from_buffer(data)
            addr = ctypes.addressof(ctypes_buffer)
            return self._lock_memory_at(addr, len(data))
        except Exception as e:
            logger.debug(f"Memory lock failed: {e}")
            return False

    def unlock_memory(self, data: bytearray) -> bool:
        """
        Unlock previously locked bytearray memory.

        Args:
            data: Bytearray to unlock

        Returns:
            True if successfully unlocked, False otherwise
        """
        if not isinstance(data, bytearray):
            return False

        if not self.enabled or not self.has_mlock or not data:
            return False

        try:
            ctypes_buffer = (ctypes.c_char * len(data)).from_buffer(data)
            addr = ctypes.addressof(ctypes_buffer)
            return self._unlock_memory_at(addr, len(data))
        except Exception as e:
            logger.debug(f"Memory unlock failed: {e}")
            return False

    def zero_memory(self, data: bytearray) -> None:
        """
        Securely zero a bytearray's memory contents.

        IMPORTANT: Only works with mutable bytearray objects.
        Python's immutable bytes cannot be securely zeroed.

        Args:
            data: Bytearray to zero
        """
        if not self.enabled or not data:
            return

        if not isinstance(data, bytearray):
            logger.warning(
                "zero_memory() called with non-bytearray. "
                "Python bytes are immutable and cannot be securely zeroed. "
                "Use bytearray or create_secure_buffer() instead."
            )
            return

        try:
            # Get correct address via ctypes
            ctypes_buffer = (ctypes.c_char * len(data)).from_buffer(data)
            addr = ctypes.addressof(ctypes_buffer)

            # Use platform-specific zeroing
            self._zero_memory_at(addr, len(data))

            # Also zero at Python level for defense in depth
            for i in range(len(data)):
                data[i] = 0

            logger.debug(f"Zeroed bytearray: {len(data)} bytes")

        except Exception as e:
            logger.warning(f"Memory zeroing error: {e}")
            # Fallback: zero at Python level only
            try:
                for i in range(len(data)):
                    data[i] = 0
            except Exception:
                pass

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
            "supports_full_protection": self.protection_level == MemoryProtectionLevel.FULL,
            "page_size": self._page_size
        }


# Global secure memory instance
_secure_memory: Optional[SecureMemory] = None


def _get_secure_memory() -> SecureMemory:
    """Get or create the global SecureMemory instance."""
    global _secure_memory
    if _secure_memory is None:
        _secure_memory = SecureMemory()
    return _secure_memory


@contextmanager
def secure_bytearray(data: Union[bytes, bytearray], lock: bool = True):
    """
    Context manager for secure bytearray handling with automatic cleanup.

    Provides:
    - Proper memory address handling via ctypes
    - Optional memory locking to prevent swapping
    - Guaranteed memory zeroing on exit (both native and Python level)
    - Automatic cleanup even if exceptions occur

    Args:
        data: Data to protect (bytes or bytearray, will be converted to bytearray)
        lock: Whether to attempt memory locking (default: True)

    Yields:
        SecureBuffer containing the protected data

    Example:
        payload = json.dumps({"secret": "data"}).encode('utf-8')
        with secure_bytearray(payload) as buf:
            encrypted = encrypt(buf.data)
            # Use encrypted data...
        # Memory automatically zeroed here

    Note:
        Memory locking may fail without appropriate privileges.
        In that case, only zeroing is performed (still provides value).
    """
    sm = _get_secure_memory()
    secure_buf = sm.create_secure_buffer(data)

    try:
        if lock:
            locked = secure_buf.lock()
            if locked:
                logger.debug(f"Memory locked: {len(secure_buf)} bytes")
            else:
                logger.debug(
                    f"Memory locking not available for {len(secure_buf)} bytes, "
                    "using zeroing only"
                )

        yield secure_buf

    finally:
        # Always zero memory
        secure_buf.zero()
        logger.debug(f"Memory zeroed: {len(secure_buf)} bytes")

        # Unlock if we attempted locking
        if lock:
            secure_buf.unlock()
            logger.debug(f"Memory unlocked: {len(secure_buf)} bytes")


# Legacy API - maintained for backwards compatibility
@contextmanager
def secure_bytes(data: bytes, lock: bool = True):
    """
    DEPRECATED: Use secure_bytearray() instead.

    This function is maintained for backwards compatibility but provides
    weaker security guarantees. Python's immutable bytes cannot be securely
    zeroed in place.

    Args:
        data: Bytes to protect
        lock: Whether to attempt memory locking

    Yields:
        SecureBuffer (use .data attribute for the bytearray)
    """
    logger.warning(
        "secure_bytes() is deprecated. Use secure_bytearray() instead. "
        "The original bytes object cannot be securely zeroed."
    )
    with secure_bytearray(data, lock) as buf:
        yield buf


def get_memory_protection_info() -> dict:
    """
    Get information about available memory protection features.

    Returns:
        Dictionary with platform and capability information
    """
    return _get_secure_memory().get_protection_info()


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
