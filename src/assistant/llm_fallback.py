"""One-shot LLM fallback client using local Ollama for ambiguous log field labeling."""

import os
import json
import logging
import urllib.parse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class OllamaFallback:
    """Provides a single one-shot prompt to a local Ollama instance for ambiguous field labeling."""

    def __init__(
        self,
        endpoint: Optional[str] = None,
        model: str = "phi4-mini",
        timeout: float = 2.0,
    ):
        if endpoint:
            self.endpoint = endpoint
            parsed = urllib.parse.urlparse(endpoint)
            self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        else:
            self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
            self.endpoint = f"{self.base_url}/api/generate"
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """Check if local Ollama server is active and reachable within timeout."""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                headers={"User-Agent": "ULPF-AutoMapping/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except Exception:
            return False

    def suggest_mappings(
        self,
        raw_samples: List[str],
        ambiguous_fields: List[str],
        known_mappings: Dict[str, str],
    ) -> Dict[str, str]:
        """
        Request field mappings for ambiguous columns.
        Returns a dict of {raw_field_name: dotted_ocsf_path}.
        Gracefully returns {} if Ollama is offline or fails.
        """
        if not ambiguous_fields or not raw_samples:
            return {}

        prompt = (
            "You are an OCSF cybersecurity schema expert. "
            "Given the following raw perimeter log samples and ambiguous fields, "
            "suggest the appropriate dotted OCSF path (e.g., 'src_endpoint.ip', 'dst_endpoint.port', "
            "'traffic.bytes', 'user.name', 'firewall_rule.name', 'finding_info.title', or 'unmapped') "
            "for each ambiguous field. Return ONLY a valid JSON object mapping each field name to its OCSF path.\n\n"
            f"Known mappings already identified: {json.dumps(known_mappings)}\n"
            f"Ambiguous fields needing labels: {json.dumps(ambiguous_fields)}\n"
            f"Raw log sample lines:\n" + "\n".join(raw_samples[:5])
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "ULPF-AutoMapping/1.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    response_text = body.get("response", "{}")
                    parsed_json = json.loads(response_text)
                    if isinstance(parsed_json, dict):
                        return {
                            str(k): str(v)
                            for k, v in parsed_json.items()
                            if k in ambiguous_fields
                        }
        except Exception as e:
            logger.debug(f"Ollama fallback unavailable or timed out: {e}")

        return {}
