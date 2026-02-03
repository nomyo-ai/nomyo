# Installation Guide

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

### Install from PyPI (recommended)

```bash
pip install nomyo
```

### Install from source

```bash
# Clone the repository
git clone https://github.com/nomyo-ai/nomyo.git
cd nomyo

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Dependencies

The NOMYO client requires the following dependencies:

- `cryptography` - Cryptographic primitives (RSA, AES, etc.)
- `httpx` - Async HTTP client
- `anyio` - Async compatibility layer

These are automatically installed when you install the package via pip.

## Virtual Environment (Recommended)

It's recommended to use a virtual environment to avoid conflicts with other Python packages:

```bash
# Create virtual environment
python -m venv nomyo_env

# Activate virtual environment
source nomyo_env/bin/activate  # On Linux/Mac
# or
nomyo_env\Scripts\activate     # On Windows

# Install nomyo
pip install nomyo
```

## Verify Installation

To verify the installation worked correctly:

```python
import nomyo
print("NOMYO client installed successfully!")
```

## Development Installation

For development purposes, you can install the package in development mode:

```bash
pip install -e .[dev]
```

This will install additional development dependencies.
