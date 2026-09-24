import os
import unittest
from unittest.mock import patch

from core.security_analyst import ClaudeAnalyst, GeminiAnalyst, QwenAnalyst


class ProviderStructuredOutputTests(unittest.TestCase):
    def setUp(self):
        self.schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "minLength": 1, "maxLength": 20},
                "score": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": ["summary", "score"],
            "additionalProperties": False,
        }

    def test_claude_uses_native_json_schema_and_leaves_local_constraints_to_pydantic(self):
        with patch.dict(os.environ, {"NMAP_ANTHROPIC_API_KEY": "test-key"}):
            with patch.object(
                ClaudeAnalyst,
                "_post_json",
                return_value={"content": [{"type": "text", "text": "{}"}]},
            ) as post_json:
                analyst = ClaudeAnalyst("claude-haiku-4-5-20251001")
                analyst._complete("system", "user", self.schema)

        body = post_json.call_args.args[1]
        sent_schema = body["output_config"]["format"]["schema"]
        self.assertEqual(body["output_config"]["format"]["type"], "json_schema")
        self.assertNotIn("minLength", sent_schema["properties"]["summary"])
        self.assertNotIn("minimum", sent_schema["properties"]["score"])

    def test_gemini_uses_native_json_schema_mode(self):
        response = {
            "candidates": [{"content": {"parts": [{"text": "{}"}]}}]
        }
        with patch.dict(os.environ, {"NMAP_GEMINI_API_KEY": "test-key"}):
            with patch.object(GeminiAnalyst, "_post_json", return_value=response) as post_json:
                analyst = GeminiAnalyst("gemini-3.5-flash")
                analyst._complete("system", "user", self.schema)

        body = post_json.call_args.args[1]
        output_format = body["generationConfig"]["responseFormat"]["text"]
        self.assertEqual(output_format["mimeType"], "application/json")
        self.assertEqual(output_format["schema"]["required"], ["summary", "score"])

    def test_qwen_uses_json_object_mode_for_local_schema_validation(self):
        response = {"choices": [{"message": {"content": "{}"}}]}
        with patch.dict(os.environ, {"NMAP_QWEN_API_KEY": "test-key"}):
            with patch.object(QwenAnalyst, "_post_json", return_value=response) as post_json:
                analyst = QwenAnalyst("qwen-plus")
                analyst._complete("system", "user", self.schema)

        body = post_json.call_args.args[1]
        self.assertEqual(body["response_format"], {"type": "json_object"})


if __name__ == "__main__":
    unittest.main()
