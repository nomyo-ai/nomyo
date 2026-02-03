# Examples

## Basic Usage Examples

### Simple Chat Completion

```python
import asyncio
from nomyo import SecureChatCompletion

async def simple_chat():
    client = SecureChatCompletion(api_key="your-api-key-here")

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello, how are you?"}
        ],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(simple_chat())
```

### Chat with System Message

```python
import asyncio
from nomyo import SecureChatCompletion

async def chat_with_system():
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

asyncio.run(chat_with_system())
```

## Advanced Usage Examples

### Using Different Security Tiers

```python
import asyncio
from nomyo import SecureChatCompletion

async def security_tiers():
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Standard security
    response1 = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "General query"}],
        security_tier="standard"
    )

    # High security for sensitive data
    response2 = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Bank account info"}],
        security_tier="high"
    )

    # Maximum security for classified data
    response3 = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Medical records"}],
        security_tier="maximum"
    )

asyncio.run(security_tiers())
```

### Using Tools

```python
import asyncio
from nomyo import SecureChatCompletion

async def chat_with_tools():
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

asyncio.run(chat_with_tools())
```

### Error Handling

```python
import asyncio
from nomyo import SecureChatCompletion, AuthenticationError, InvalidRequestError

async def error_handling():
    client = SecureChatCompletion(api_key="your-api-key-here")

    try:
        response = await client.create(
            model="Qwen/Qwen3-0.6B",
            messages=[{"role": "user", "content": "Hello"}]
        )
        print(response['choices'][0]['message']['content'])
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
    except InvalidRequestError as e:
        print(f"Invalid request: {e}")
    except Exception as e:
        print(f"Other error: {e}")

asyncio.run(error_handling())
```

### Custom Base URL

```python
import asyncio
from nomyo import SecureChatCompletion

async def custom_base_url():
    # For local development
    client = SecureChatCompletion(
        base_url="https://NOMYO-PRO-ROUTER:12435",
        allow_http=True
    )

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Hello"}]
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(custom_base_url())
```

### API Key Authentication

```python
import asyncio
from nomyo import SecureChatCompletion

async def api_key_auth():
    # Initialize with API key
    client = SecureChatCompletion(
        api_key="your-api-key-here"
    )

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Hello"}]
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(api_key_auth())
```

## Real-World Scenarios

### Chat Application with History

```python
import asyncio
from nomyo import SecureChatCompletion

class SecureChatApp:
    def __init__(self):
        self.client = SecureChatCompletion(api_key="your-api-key-here")
        self.conversation_history = []

    async def chat(self, message):
        # Add user message to history
        self.conversation_history.append({"role": "user", "content": message})

        # Get response from the model
        response = await self.client.create(
            model="Qwen/Qwen3-0.6B",
            messages=self.conversation_history,
            temperature=0.7
        )

        # Add assistant response to history
        assistant_message = response['choices'][0]['message']
        self.conversation_history.append(assistant_message)

        return assistant_message['content']

async def main():
    app = SecureChatApp()

    # First message
    response1 = await app.chat("Hello, what's your name?")
    print(f"Assistant: {response1}")

    # Second message
    response2 = await app.chat("Can you tell me about secure chat clients?")
    print(f"Assistant: {response2}")

asyncio.run(main())
```

### Data Processing with Tools

```python
import asyncio
from nomyo import SecureChatCompletion

async def data_processing():
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Process data with tool calling
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Process this data: 100, 200, 300, 400"}
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "calculate_statistics",
                    "description": "Calculate statistical measures",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "array", "items": {"type": "number"}}
                        },
                        "required": ["data"]
                    }
                }
            }
        ]
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(data_processing())
```

### Batch Processing

```python
import asyncio
from nomyo import SecureChatCompletion

async def batch_processing():
    client = SecureChatCompletion(api_key="your-api-key-here")

    # Process multiple queries concurrently
    tasks = []

    queries = [
        "What is the weather today?",
        "Tell me about Python programming",
        "How to learn machine learning?"
    ]

    for query in queries:
        task = client.create(
            model="Qwen/Qwen3-0.6B",
            messages=[{"role": "user", "content": query}],
            temperature=0.7
        )
        tasks.append(task)

    # Execute all queries in parallel
    responses = await asyncio.gather(*tasks)

    for i, response in enumerate(responses):
        print(f"Query {i+1}: {response['choices'][0]['message']['content'][:100]}...")

asyncio.run(batch_processing())
```

## Configuration Examples

### Custom Client Configuration

```python
import asyncio
from nomyo import SecureChatCompletion

async def custom_config():
    # Create a client with custom configuration
    client = SecureChatCompletion(
        allow_http=False,  # Force HTTPS
        api_key="your-api-key",
        secure_memory=True  # Explicitly enable secure memory protection (default)
    )

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Hello"}],
        temperature=0.7
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(custom_config())
```

### Environment-Based Configuration (strongly recommended)

```python
import asyncio
import os
from nomyo import SecureChatCompletion

async def env_config():
    # Load configuration from environment variables
    api_key = os.getenv('NOMYO_API_KEY')

    client = SecureChatCompletion(
        api_key=api_key
    )

    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[{"role": "user", "content": "Hello"}]
    )

    print(response['choices'][0]['message']['content'])

asyncio.run(env_config())
```

## 
