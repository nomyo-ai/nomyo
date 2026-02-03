# Getting Started

## Basic Usage

The NOMYO client provides end-to-end encryption (E2E) for all communications between your application and the NOMYO inference endpoints. This ensures that your prompts and responses are protected from unauthorized access or interception.

The NOMYO client provides the same interface as OpenAI's ChatCompletion API, making it easy to integrate into existing code.

The encryption and decryption process is causing overhead, thus inference speed will be lower compared to unencrypted inference. Using high and maximum security_tiers in the client request will add additional latency to the round-trip-time, but guarantees highest confidential use cases.

To minimize en-/decryption overhead the API is **none**-streaming. OpenAI API compatibily allows to set streaming=True in the request, but this will be ignored on the server side to allow maximum response token generation.

### Simple Chat Completion

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    # Initialize client
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Simple chat completion
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello! How are you today?"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

### With System Messages

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(api_key="your-api-key-here")

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

## API Key Authentication

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    # Initialize with API key (recommended for production)
    client = SecureChatCompletion(
        api_key="your-api-key-here"
    )

    # Or pass API key in the create() method
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello!"}
        ],
        api_key="your-api-key-here"  # Overrides instance API key
    )

asyncio.run(main())
```

## Security Tiers

The client supports different security tiers for controlling data protection levels:

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Standard security tier (default)
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello!"}
        ],
        security_tier="standard"
    )

    # High security tier for sensitive data
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "What's my bank account balance?"}
        ],
        security_tier="high" #enforces secure tokenizer
    )

    # Maximum security tier for classified data
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Share my personal medical records"}
        ],
        security_tier="maximum" #HIPAA PHI compliance or other confidential use cases
    )

asyncio.run(main())
```

## Using Tools

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(api_key="your-api-key-here")

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "What's the weather in Paris?"}
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather information",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"}
                        },
                        "required": ["location"]
                    }
                }
            }
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

## Async Alias

The client also provides an `acreate` async alias for convenience:

```python
import asyncio
from nomyo import SecureChatCompletion

async def main():
    client = SecureChatCompletion(api_key="your-api-key-here")

    response = await client.acreate(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello!"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(main())
```

## Error Handling

```python
import asyncio
from nomyo import SecureChatCompletion, AuthenticationError, InvalidRequestError

async def main():
    client = SecureChatCompletion(base_url="https://api.nomyo.ai:12434")

    try:
        response = await client.create(
            model="Qwen/Qwen3-0.6B",
            messages=[
                {"role": "user", "content": "Hello!"}
            ]
        )
        print(response['choices'][0]['message']['content'])
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
    except InvalidRequestError as e:
        print(f"Invalid request: {e}")
    except Exception as e:
        print(f"Other error: {e}")

asyncio.run(main())
```
