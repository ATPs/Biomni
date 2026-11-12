"""Explicit compatible API model with no dependency on a provider SDK."""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from typing import Literal

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from pydantic import Field, SecretStr


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class CompatibleChatModel(BaseChatModel):
    base_url: str
    model: str
    api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    protocol: Literal["chat_completions", "responses"] = "chat_completions"
    temperature: float = 0.7
    timeout: float = Field(default=600, gt=0)

    @property
    def _llm_type(self):
        return "compatible-http"

    @property
    def _identifying_params(self):
        return {"model": self.model, "protocol": self.protocol}

    def _payload(self, messages, *, stream=False, stop=None):
        items = []
        for message in messages:
            role = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}.get(message.type, "user")
            if role == "tool":
                if self.protocol == "responses":
                    items.append({"type": "function_call_output", "call_id": message.tool_call_id, "output": message.content})
                else:
                    items.append({"role": role, "content": message.content, "tool_call_id": message.tool_call_id})
            else:
                items.append({"role": role, "content": message.content})
        payload = {"model": self.model, "stream": stream}
        if self.protocol == "chat_completions":
            payload.update(messages=items, temperature=self.temperature)
            if stop:
                payload["stop"] = stop
        else:
            payload.update(input=items, store=False)
        return payload

    def _open(self, payload):
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Invalid compatible API base URL")
        suffix = "chat/completions" if self.protocol == "chat_completions" else "responses"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = self.api_key.get_secret_value()
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self.base_url.rstrip("/") + "/" + suffix,
                          data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            return build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=self.timeout)
        except HTTPError as exc:
            raise RuntimeError(f"Model endpoint returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError):
            raise RuntimeError("Configured model endpoint unavailable") from None

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        with self._open(self._payload(messages, stop=stop)) as response:
            body = json.load(response)
        if self.protocol == "chat_completions":
            text = body["choices"][0]["message"].get("content") or ""
        else:
            text = "".join(part.get("text", "") for item in body.get("output", [])
                           for part in item.get("content", []) if part.get("type") == "output_text")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))],
                          llm_output={"token_usage": body.get("usage"), "model_name": self.model})

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        # A1 uses text tags, so streamed function-call deltas are not requested.
        with self._open(self._payload(messages, stream=True, stop=stop)) as response:
            lines, pending = [], ""
            for raw in response:
                line = raw.decode("utf-8").rstrip(chr(13) + chr(10))
                if line.startswith("data:"):
                    lines.append(line[5:].strip())
                    continue
                if line or not lines:
                    continue
                data, lines = chr(10).join(lines), []
                if data == "[DONE]":
                    break
                event = json.loads(data)
                if self.protocol == "chat_completions":
                    choices = event.get("choices", [])
                    text = choices[0].get("delta", {}).get("content", "") if choices else ""
                else:
                    text = event.get("delta", "") if event.get("type") == "response.output_text.delta" else ""
                pending += text or ""
                hits = [pending.find(s) for s in stop or [] if s and s in pending]
                if hits:
                    text = pending[:min(hits)]
                    if text:
                        yield ChatGenerationChunk(message=AIMessageChunk(content=text))
                    return
                keep = max([len(s) - 1 for s in stop or [] if s] or [0])
                count = max(0, len(pending) - keep)
                if count:
                    chunk = ChatGenerationChunk(message=AIMessageChunk(content=pending[:count]))
                    pending = pending[count:]
                    if run_manager:
                        run_manager.on_llm_new_token(chunk.text, chunk=chunk)
                    yield chunk
            if pending:
                yield ChatGenerationChunk(message=AIMessageChunk(content=pending))
