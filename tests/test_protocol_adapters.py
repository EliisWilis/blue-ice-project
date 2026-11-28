from __future__ import annotations

from aegis.protocol_adapters import (
    anthropic_to_chat,
    chat_to_anthropic,
    chat_to_gemini,
    gemini_to_chat,
)


def test_anthropic_messages_translation_preserves_system_tools_and_results():
    payload = anthropic_to_chat(
        {
            "model": "claude-test",
            "system": "Be concise",
            "messages": [
                {"role": "user", "content": "Find it"},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "call_1", "name": "lookup", "input": {"q": "x"}}
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "call_1", "content": "done"}
                    ],
                },
            ],
            "tools": [
                {"name": "lookup", "description": "Look up", "input_schema": {"type": "object"}}
            ],
        }
    )
    assert payload["messages"][0] == {"role": "system", "content": "Be concise"}
    assert payload["messages"][2]["tool_calls"][0]["function"]["name"] == "lookup"
    assert payload["messages"][3]["role"] == "tool"
    assert payload["tools"][0]["type"] == "function"


def test_chat_to_anthropic_maps_text_and_tool_use():
    result = chat_to_anthropic(
        {
            "id": "chat_1",
            "choices": [
                {
                    "message": {
                        "content": "Done",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "function": {"name": "lookup", "arguments": '{"q":"x"}'},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
        },
        model="claude-test",
    )
    assert result["content"][0] == {"type": "text", "text": "Done"}
    assert result["content"][1]["type"] == "tool_use"
    assert result["content"][1]["input"] == {"q": "x"}
    assert result["stop_reason"] == "tool_use"


def test_gemini_translation_maps_system_and_generation_config():
    result = gemini_to_chat(
        {
            "systemInstruction": {"parts": [{"text": "Be safe"}]},
            "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 100},
        }
    )
    assert result["messages"] == [
        {"role": "system", "content": "Be safe"},
        {"role": "user", "content": "Hello"},
    ]
    assert result["max_tokens"] == 100
    assert chat_to_gemini({"choices": [{"message": {"content": "Hi"}}]})["candidates"][0][
        "content"
    ]["parts"] == [{"text": "Hi"}]
