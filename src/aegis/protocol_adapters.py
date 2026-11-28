"""Protocol translation helpers for native coding-agent APIs.

The adapters translate only between wire formats. They do not perform HTTP,
credential handling, policy checks, or logging; callers must run translated
payloads through the normal Blue Ice security pipeline.
"""

from __future__ import annotations

from typing import Any


def _text_from_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    parts: list[str] = []
    for block in value:
        if not isinstance(block, dict):
            continue
        if block.get("type") in {"text", "input_text", "output_text"}:
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def anthropic_to_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate an Anthropic Messages request to Chat Completions."""
    if not isinstance(payload, dict):
        raise ValueError("Anthropic request must be a JSON object")
    model = payload.get("model")
    messages = payload.get("messages")
    if not isinstance(model, str) or not model.strip():
        raise ValueError("Anthropic model must be a non-empty string")
    if not isinstance(messages, list) or not messages:
        raise ValueError("Anthropic messages must be a non-empty array")

    translated: list[dict[str, Any]] = []
    system = payload.get("system")
    if system is not None:
        system_text = _text_from_content(system)
        if system_text:
            translated.append({"role": "system", "content": system_text})

    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {"user", "assistant"}:
            raise ValueError("Anthropic messages must have user or assistant roles")
        role = message["role"]
        content = message.get("content", "")
        if isinstance(content, str):
            translated.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            raise ValueError("Anthropic message content must be text or blocks")
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text" and isinstance(block.get("text"), str):
                text_parts.append(block["text"])
            elif kind == "tool_use":
                name = block.get("name")
                call_id = block.get("id")
                if not isinstance(name, str) or not isinstance(call_id, str):
                    raise ValueError("Anthropic tool_use requires id and name")
                tool_calls.append(
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": _json_arguments(block.get("input", {})),
                        },
                    }
                )
            elif kind == "tool_result":
                call_id = block.get("tool_use_id")
                if not isinstance(call_id, str):
                    raise ValueError("Anthropic tool_result requires tool_use_id")
                tool_results.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": _text_from_content(block.get("content", "")),
                    }
                )
        if role == "assistant":
            item: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
            if tool_calls:
                item["tool_calls"] = tool_calls
            translated.append(item)
        else:
            if text_parts:
                translated.append({"role": "user", "content": "".join(text_parts)})
            translated.extend(tool_results)

    result: dict[str, Any] = {"model": model, "messages": translated, "stream": False}
    for source, target in (
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stop_sequences", "stop"),
    ):
        if source in payload:
            result[target] = payload[source]
    if isinstance(payload.get("tools"), list):
        result["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                },
            }
            for t in payload["tools"]
            if isinstance(t, dict) and isinstance(t.get("name"), str)
        ]
    if payload.get("stream") is True:
        result["stream"] = False  # Blue Ice buffers upstream output before replay.
    return result


def _json_arguments(value: Any) -> str:
    import json

    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        raise ValueError("tool input must be JSON-compatible") from None


def chat_to_anthropic(response: dict[str, Any], *, model: str) -> dict[str, Any]:
    """Translate a Chat Completions response to an Anthropic message."""
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("Chat response has no usable choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("Chat response has no usable message")
    content: list[dict[str, Any]] = []
    text = message.get("content")
    if isinstance(text, str) and text:
        content.append({"type": "text", "text": text})
    for call in (
        message.get("tool_calls", []) if isinstance(message.get("tool_calls"), list) else []
    ):
        if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
            continue
        function = call["function"]
        content.append(
            {
                "type": "tool_use",
                "id": call.get("id", "call_unknown"),
                "name": function.get("name", "unknown"),
                "input": _parse_arguments(function.get("arguments", "{}")),
            }
        )
    finish = choices[0].get("finish_reason")
    stop_reason = (
        "tool_use"
        if finish == "tool_calls" or any(item["type"] == "tool_use" for item in content)
        else "end_turn"
    )
    usage = response.get("usage", {})
    return {
        "id": response.get("id", "msg_blue_ice"),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
        },
    }


def chat_to_anthropic_sse(response: dict[str, Any], *, model: str) -> bytes:
    """Create a buffered Anthropic SSE replay from a completed chat response."""
    import json

    message = chat_to_anthropic(response, model=model)
    frames: list[tuple[str, dict[str, Any]]] = [
        ("message_start", {"type": "message_start", "message": {**message, "content": []}})
    ]
    for index, block in enumerate(message["content"]):
        frames.append(
            (
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": block},
            )
        )
        if block.get("type") == "text":
            frames.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": block["text"]},
                    },
                )
            )
        frames.append(("content_block_stop", {"type": "content_block_stop", "index": index}))
    frames.extend(
        [
            (
                "message_delta",
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                    "usage": message["usage"],
                },
            ),
            ("message_stop", {"type": "message_stop"}),
        ]
    )
    return "".join(
        f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'), ensure_ascii=False)}\n\n"
        for name, data in frames
    ).encode("utf-8")


def _parse_arguments(value: Any) -> Any:
    import json

    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return {}


def gemini_to_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate Gemini generateContent JSON to Chat Completions."""
    if not isinstance(payload, dict):
        raise ValueError("Gemini request must be a JSON object")
    contents = payload.get("contents")
    if not isinstance(contents, list) or not contents:
        raise ValueError("Gemini contents must be a non-empty array")
    messages: list[dict[str, Any]] = []
    system = payload.get("systemInstruction")
    if isinstance(system, dict):
        text = _gemini_parts_text(system.get("parts"))
        if text:
            messages.append({"role": "system", "content": text})
    for content in contents:
        if not isinstance(content, dict):
            continue
        role = "assistant" if content.get("role") == "model" else "user"
        parts = content.get("parts", [])
        text = _gemini_parts_text(parts)
        if text:
            messages.append({"role": role, "content": text})
    result: dict[str, Any] = {
        "model": str(payload.get("model", "gemini")),
        "messages": messages,
        "stream": False,
    }
    generation = payload.get("generationConfig")
    if isinstance(generation, dict):
        for source, target in (
            ("temperature", "temperature"),
            ("topP", "top_p"),
            ("maxOutputTokens", "max_tokens"),
            ("stopSequences", "stop"),
        ):
            if source in generation:
                result[target] = generation[source]
    return result


def _gemini_parts_text(parts: Any) -> str:
    if not isinstance(parts, list):
        return ""
    return "".join(
        part.get("text", "")
        for part in parts
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    )


def chat_to_gemini(response: dict[str, Any]) -> dict[str, Any]:
    """Translate a Chat Completions response to Gemini generateContent."""
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("Chat response has no usable choices")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise ValueError("Chat response has no usable message")
    parts: list[dict[str, Any]] = []
    if isinstance(message.get("content"), str) and message["content"]:
        parts.append({"text": message["content"]})
    return {
        "candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP"}],
        "usageMetadata": {
            "promptTokenCount": response.get("usage", {}).get("prompt_tokens", 0),
            "candidatesTokenCount": response.get("usage", {}).get("completion_tokens", 0),
        },
    }


def chat_to_gemini_sse(response: dict[str, Any]) -> bytes:
    """Create a buffered Gemini SSE replay from a completed chat response."""
    import json

    return (
        "data: "
        + json.dumps(chat_to_gemini(response), separators=(",", ":"), ensure_ascii=False)
        + "\n\n"
    ).encode("utf-8")
