import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from biomni.config import BiomniConfig, config_context, effective_config

AGENT_AVAILABLE = (
    importlib.util.find_spec("langchain_core") is not None and importlib.util.find_spec("langgraph") is not None
)


class ConfigTests(unittest.TestCase):
    def test_alias_redaction_and_context_isolation(self):
        first = BiomniConfig(llm="first", api_key="do-not-print")
        second = BiomniConfig(llm="second")
        self.assertEqual(first.llm_model, "first")
        first.llm_model = "changed"
        self.assertEqual(first.llm, "changed")
        self.assertNotIn("do-not-print", repr(first))
        self.assertNotIn("do-not-print", json.dumps(first.to_dict()))
        with config_context(first):
            self.assertIs(effective_config(), first)
            with config_context(second):
                self.assertIs(effective_config(), second)
            self.assertIs(effective_config(), first)


@unittest.skipUnless(AGENT_AVAILABLE, "Run agent tests in the existing biomni environment")
class AgentTests(unittest.TestCase):
    def test_fake_model_local_profile_does_not_download_or_leak_keys(self):
        from biomni.agent.a1 import A1
        from biomni.localenv import RuntimeProfile
        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        with tempfile.TemporaryDirectory() as tmp:
            profile = RuntimeProfile(agent_python=sys.executable, data_path=tmp)
            fake = FakeListChatModel(responses=["<solution>fixture complete</solution>"])
            output = io.StringIO()
            with (
                patch("biomni.agent.a1.get_llm", return_value=fake),
                patch("biomni.agent.a1.check_and_download_s3_files", side_effect=AssertionError("Unexpected download")),
                contextlib.redirect_stdout(output),
            ):
                agent = A1(
                    runtime_profile=profile, llm="local-model", api_key="task-fixture-secret", use_tool_retriever=False
                )
                result = agent.go("Reply without calling tools")
            self.assertIn("fixture complete", result[1])
            self.assertIn("search_local_capabilities", agent._custom_functions)
            self.assertNotIn("task-fixture-secret", output.getvalue())

    def test_database_context_propagates_to_execution_thread(self):
        from biomni.utils import run_with_timeout

        config = BiomniConfig(llm="task-specific")
        with config_context(config):
            self.assertEqual(run_with_timeout(lambda: effective_config().llm, timeout=3), "task-specific")

    def test_explicit_chat_and_responses_without_provider_sdk(self):
        from biomni.llm import get_llm
        from langchain_core.messages import HumanMessage

        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path, body, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                result = (
                    {"choices": [{"message": {"content": "chat works"}}]}
                    if self.path.endswith("completions")
                    else {
                        "output": [{"type": "message", "content": [{"type": "output_text", "text": "responses works"}]}]
                    }
                )
                self.wfile.write(json.dumps(result).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for protocol in ("chat_completions", "responses"):
                llm = get_llm(
                    model="gpt-6.1-sol",
                    base_url=f"http://127.0.0.1:{server.server_port}/v1",
                    api_key="task-only",
                    protocol=protocol,
                )
                self.assertIn("works", llm.invoke([HumanMessage(content="hello")]).content)
                self.assertNotIn("task-only", repr(llm))
            self.assertEqual([item[0] for item in seen], ["/v1/chat/completions", "/v1/responses"])
            self.assertNotIn("stop", seen[1][1])
            self.assertNotIn("temperature", seen[1][1])
            self.assertEqual(seen[0][2], "Bearer task-only")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
