# Secure Memory Operations

## Overview

NOMYO now includes client-side secure memory operations to protect sensitive data in memory. This feature prevents plaintext payloads from being swapped to disk and guarantees memory is zeroed after encryption.

## Features

- **Cross-platform support**: Linux, Windows, macOS
- **Memory locking**: Prevents sensitive data from being swapped to disk
- **Guaranteed zeroing**: Memory is cleared immediately after use
- **Context managers**: Automatic cleanup even on exceptions
- **Backward compatible**: Works even if secure memory is not available
- **Configurable**: Can be enabled/disabled per client instance

## Security Benefits

1. **Prevent memory swapping**: Sensitive data won't be written to disk via swap files
2. **Guaranteed zeroing**: Memory is cleared immediately after encryption
3. **Protection against memory dumping**: Reduces risk from memory analysis tools
4. **Automatic cleanup**: Context managers ensure cleanup even on exceptions

## Usage

### Basic Usage

```python
from nomyo import SecureChatCompletion

# Create client with secure memory enabled (default)
client = SecureChatCompletion(
    base_url="https://api.nomyo.ai:12434",
    secure_memory=True  # Enabled by default
)

# Use as normal - payloads are automatically protected
response = await client.create(
    model="Qwen/Qwen3-0.6B",
    messages=[{"role": "user", "content": "Sensitive data"}]
)
```

### Disabling Secure Memory

```python
from nomyo import SecureChatCompletion

# Disable secure memory for testing or when not needed
client = SecureChatCompletion(
    base_url="https://api.nomyo.ai:12434",
    secure_memory=False
)
```

### Global Configuration

```python
from nomyo import disable_secure_memory, enable_secure_memory, get_memory_protection_info

# Disable globally
disable_secure_memory()

# Enable globally
enable_secure_memory()

# Check current status
info = get_memory_protection_info()
print(f"Secure memory enabled: {info['enabled']}")
print(f"Platform: {info['platform']}")
print(f"Protection level: {info['protection_level']}")
```

### Using Secure Bytes Directly

```python
from nomyo import secure_bytes

# Protect sensitive data
sensitive_data = b"Secret information"
with secure_bytes(sensitive_data) as protected:
    # Data is locked in memory and will be zeroed on exit
    process(protected)

# Memory automatically zeroed here
```

## Platform Support

| Platform | Memory Locking | Secure Zeroing | Protection Level |
|----------|----------------|----------------|------------------|
| Linux    | ✓ (mlock)     | ✓ (memset)    | Full             |
| Windows  | ✓ (VirtualLock) | ✓ (RtlSecureZeroMemory) | Full |
| macOS    | ✓ (mlock)     | ✓ (memset)    | Full             |
| Other    | ✗              | ✓ (fallback)  | Zeroing only     |

## Implementation Details

### Memory Locking

- **Linux/macOS**: Uses `mlock()` system call to lock memory pages
- **Windows**: Uses `VirtualLock()` API to lock memory pages
- **Fallback**: If memory locking fails, only zeroing is performed

### Memory Zeroing

- **bytearray**: Zeroed in-place for maximum security
- **bytes**: Best-effort approach (Python's immutable bytes)
- **Automatic**: Always performed when exiting context manager

### Error Handling

- **Graceful degradation**: If memory locking fails, continues with zeroing
- **No exceptions**: Operations continue even if security features unavailable
- **Logging**: Detailed logs for debugging security issues

## Best Practices

1. **Keep secure memory enabled** in production environments
2. **Use HTTPS** for all communications (enabled by default)
3. **Encrypt sensitive data** before processing
4. **Minimize plaintext lifetime** - encrypt as soon as possible
5. **Monitor security logs** for any issues with memory protection

## Troubleshooting

### Memory Locking Failures

**Error**: `mlock permission denied`

**Solution**: Grant `CAP_IPC_LOCK` capability or increase `ulimit -l`

```bash
# Temporary solution
sudo prlimit --memlock=unlimited --pid $$

# Permanent solution (Linux)
sudo setcap cap_ipc_lock=ep $(which python)
```

**Windows**: Usually works without special privileges

**macOS**: Usually works without special privileges

### Secure Memory Unavailable

If secure memory is not available, the system falls back to standard memory handling with a warning. This ensures the application continues to work while alerting you to the reduced security level.

## API Reference

### Classes

#### `SecureMemory`

Cross-platform secure memory handler.

**Methods**:
- `lock_memory(data: bytes) -> bool`: Lock memory to prevent swapping
- `unlock_memory(data: bytes) -> bool`: Unlock memory pages
- `zero_memory(data: bytes) -> None`: Securely zero memory
- `get_protection_info() -> dict`: Get capability information

#### Context Managers

##### `secure_bytes(data: bytes, lock: bool = True)`

Context manager for secure byte handling.

**Parameters**:
- `data`: Bytes to protect
- `lock`: Whether to attempt memory locking (default: True)

**Example**:
```python
with secure_bytes(sensitive_data) as protected:
    # Use protected data
    pass
# Memory automatically zeroed
```

### Functions

#### `get_memory_protection_info() -> dict`

Get information about available memory protection features.

**Returns**:
- Dictionary with protection status including:
  - `enabled`: Whether secure memory is enabled
  - `platform`: Current platform
  - `protection_level`: "full", "zeroing_only", or "none"
  - `has_memory_locking`: Whether memory locking is available
  - `has_secure_zeroing`: Whether secure zeroing is available
  - `supports_full_protection`: Whether full protection is available

#### `disable_secure_memory() -> None`

Disable secure memory operations globally.

#### `enable_secure_memory() -> None`

Re-enable secure memory operations globally.

## Examples

### Secure Chat Completion

```python
from nomyo import SecureChatCompletion

async def secure_chat():
    # Create client with maximum security
    client = SecureChatCompletion(
        base_url="https://api.nomyo.ai:12434",
        secure_memory=True  # Default
    )

    # All payloads are automatically protected
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "system", "content": "You are a secure assistant"},
            {"role": "user", "content": "Sensitive information here"}
        ],
        temperature=0.7
    )

    return response
```

### Secure Data Processing

```python
from nomyo import secure_bytes
import json

def process_sensitive_data(data_dict):
    # Serialize to JSON
    data_json = json.dumps(data_dict).encode('utf-8')

    # Process with secure memory
    with secure_bytes(data_json) as protected:
        # Perform operations on protected data
        result = encrypt_and_send(protected)

    return result
```

### Checking Security Status

```python
from nomyo import get_memory_protection_info

def check_security_status():
    info = get_memory_protection_info()

    print(f"Security Status:")
    print(f"  Enabled: {info['enabled']}")
    print(f"  Platform: {info['platform']}")
    print(f"  Protection Level: {info['protection_level']}")
    print(f"  Memory Locking: {info['has_memory_locking']}")
    print(f"  Secure Zeroing: {info['has_secure_zeroing']}")

    return info
```

## Security Considerations

### Memory Protection Levels

1. **Full Protection** (Linux/Windows/macOS):
   - Memory locked to prevent swapping
   - Memory zeroed after use
   - Best security available

2. **Zeroing Only** (Fallback):
   - Memory zeroed after use
   - No memory locking
   - Still provides significant security benefits

3. **None** (Disabled):
   - No memory protection
   - Standard Python memory management
   - Only for testing or non-sensitive applications

### When to Disable Secure Memory

Secure memory should only be disabled in the following scenarios:

1. **Testing**: When testing encryption/decryption without security
2. **Performance testing**: Measuring baseline performance
3. **Non-sensitive data**: When processing public/non-sensitive information
4. **Debugging**: When memory analysis is required

### Security Warnings

- **Memory locking may fail** without appropriate privileges
- **Python's memory management** limits zeroing effectiveness for immutable bytes
- **Always use HTTPS** for production deployments
- **Monitor logs** for security-related warnings

