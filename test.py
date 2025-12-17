#!/usr/bin/env python3
"""
Test script to verify OpenAI compatibility of SecureChatCompletion.

This script demonstrates that the SecureChatCompletion class provides
the same interface as OpenAI's ChatCompletion.create() method.
"""

import asyncio
from nomyo import SecureChatCompletion

client = SecureChatCompletion(base_url="http://localhost:12434", allow_http=True)

async def test_basic_chat():
    """Test basic chat completion with OpenAI-style API."""
    print("=" * 70)
    print("TEST 1: Basic Chat Completion (OpenAI-style API)")
    print("=" * 70)

    # This is how you would use OpenAI's client:
    # response = await openai.ChatCompletion.create(
    #     model="gpt-3.5-turbo",
    #     messages=[...],
    #     temperature=0.7
    # )

    # Now with SecureChatCompletion (same API!):
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        temperature=0.7,
    )

    # Verify response structure matches OpenAI format
    assert "choices" in response, "Response missing 'choices' field"
    assert len(response["choices"]) > 0, "No choices in response"
    assert "message" in response["choices"][0], "Choice missing 'message' field"
    assert "content" in response["choices"][0]["message"], "Message missing 'content' field"
    assert "finish_reason" in response["choices"][0], "Choice missing 'finish_reason' field"

    print("✅ Response structure matches OpenAI format")
    print(f"✅ Model: {response.get('model')}")
    print(f"✅ Finish Reason: {response['choices'][0].get('finish_reason')}")
    print(f"✅ Content: {response['choices'][0]['message']['content']}...")
    return True

async def test_chat_with_tools():
    """Test chat completion with tools (OpenAI-style API)."""
    print("\n" + "=" * 70)
    print("TEST 2: Chat with Tools (OpenAI-style API)")
    print("=" * 70)

    # This is how you would use OpenAI's client with tools:
    # response = await openai.ChatCompletion.create(
    #     model="gpt-3.5-turbo",
    #     messages=[...],
    #     tools=[...],
    #     temperature=0.7
    # )

    # Now with SecureChatCompletion (same API!):
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "system", "content": "You are a helpful assistant with tools."},
            {"role": "user", "content": "What's the weather in Paris?"}
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather information for a location",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {
                                "type": "string",
                                "description": "City name"
                            }
                        },
                        "required": ["location"]
                    }
                }
            }
        ],
        temperature=0.7,
        max_tokens=2000
    )

    # Verify response structure
    assert "choices" in response, "Response missing 'choices' field"
    assert "message" in response["choices"][0], "Choice missing 'message' field"

    print("✅ Response structure matches OpenAI format")
    print(f"✅ Model: {response.get('model')}")
    print(f"✅ Content: {response['choices'][0]['message']['content']}...")

    # Check for tool calls if present
    if 'tool_calls' in response['choices'][0]['message']:
        print("✅ Tool calls detected in response")
        for tool_call in response['choices'][0]['message']['tool_calls']:
            print(f"   - Function: {tool_call['function']['name']}")
    return True

async def test_all_openai_parameters():
    """Test that all common OpenAI parameters are supported."""
    print("\n" + "=" * 70)
    print("TEST 3: All OpenAI Parameters Support")
    print("=" * 70)

    # Test with various OpenAI parameters
    response = await client.create(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Hello!"}
        ],
        temperature=0.7,
        max_tokens=100,
        top_p=0.9,
        frequency_penalty=0.0,
        presence_penalty=0.0,
        stop=None,
        n=1,
        stream=False,
        user="test_user"
    )

    print("✅ All OpenAI parameters accepted")
    print(f"✅ Response received successfully")
    return True

async def test_async_alias():
    """Test the acreate async alias method."""
    print("\n" + "=" * 70)
    print("TEST 4: Async Alias (acreate)")
    print("=" * 70)

    # Test using the acreate alias on the client instance
    response = await client.acreate(
        model="Qwen/Qwen3-0.6B",
        messages=[
            {"role": "user", "content": "Test message"}
        ],
        temperature=0.7
    )

    print("✅ acreate() method works correctly")
    print(f"✅ Response received: {response['choices'][0]['message']['content']}...")
    return True

async def test_error_handling():
    """Test error handling."""
    print("\n" + "=" * 70)
    print("TEST 5: Error Handling")
    print("=" * 70)

    try:
        # This should fail gracefully
        response = await client.create(
            model="nonexistent-model",
            messages=[
                {"role": "user", "content": "Test"}
            ]
        )
        print("⚠️  Expected error did not occur")
        return False
    except Exception as e:
        print(f"✅ Error handled correctly: {type(e).__name__}")
        return True

async def main():
    """Run all compatibility tests."""
    print("=" * 70)
    print("SECURE CHAT CLIENT - OpenAI Compatibility Tests")
    print("=" * 70)
    print("\nTesting that SecureChatCompletion provides the same API as")
    print("openai.ChatCompletion.create() with end-to-end encryption...\n")

    tests = [
        test_basic_chat,
        test_chat_with_tools,
        test_all_openai_parameters,
        test_async_alias,
        test_error_handling,
    ]

    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"\n❌ Test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append(False)

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
        print("\nThe SecureChatCompletion class is fully compatible with")
        print("OpenAI's ChatCompletion.create() API while providing")
        print("end-to-end encryption for secure communication.")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

    return passed == total

if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
