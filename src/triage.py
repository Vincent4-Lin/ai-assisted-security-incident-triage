#!/usr/bin/env python3
"""AI-assisted security incident triage CLI.

The tool supports two modes:
- offline heuristic triage for demos without an API key
- OpenAI-compatible chat completions for LLM-assisted triage
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.3-70b-versatile"

REQUIRED_FIELDS = {
    "summary": str,
    "incident_type": str,
    "risk_level": str,
    "confidence": (int, float),
    "iocs": list,
    "attack_patterns": list,
    "mitre_attack": list,
    "evidence": list,
    "recommended_actions": list,
    "limitations": list,
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Input JSON must be an object.")
    return data


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def incident_to_text(incident: dict[str, Any]) -> str:
    return json.dumps(incident, indent=2, ensure_ascii=False)


def extract_iocs(text: str) -> list[dict[str, str]]:
    patterns = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "url": r"\b(?:https?|hxxps?)://[^\s\"'>]+",
        "hash": r"\b[a-fA-F0-9]{32,64}\b",
    }
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kind, pattern in patterns.items():
        for value in re.findall(pattern, text):
            normalized = value.replace("[.]", ".").rstrip(".,;)]}")
            item = (kind, normalized)
            if item not in seen:
                found.append({"type": kind, "value": normalized})
                seen.add(item)
    return found


def offline_triage(incident: dict[str, Any]) -> dict[str, Any]:
    text = incident_to_text(incident)
    lowered = text.lower()
    iocs = extract_iocs(text)

    incident_type = "suspicious security event"
    attack_patterns = []
    mitre = []
    evidence = []
    risk_level = "medium"
    confidence = 0.55

    if any(term in lowered for term in ["phishing", "verify", "mailbox", "credential"]):
        incident_type = "credential phishing and possible account compromise"
        attack_patterns.append("Credential phishing")
        mitre.append({"technique": "T1566", "name": "Phishing"})
        evidence.append("Incident notes mention a verification message and external link.")
        confidence += 0.1

    if any(term in lowered for term in ["mfa", "push", "approved"]):
        attack_patterns.append("MFA fatigue or social engineering")
        mitre.append({"technique": "T1621", "name": "Multi-Factor Authentication Request Generation"})
        evidence.append("MFA prompt activity appears in the incident notes.")
        confidence += 0.1

    if any(term in lowered for term in ["forwarding", "inbox forwarding", "external-recipient"]):
        attack_patterns.append("Mailbox rule abuse")
        mitre.append({"technique": "T1114", "name": "Email Collection"})
        evidence.append("A new inbox forwarding rule was attempted.")
        risk_level = "high"
        confidence += 0.1

    if any(term in lowered for term in ["unusual country", "successful login", "source_ip"]):
        attack_patterns.append("Suspicious authentication")
        mitre.append({"technique": "T1078", "name": "Valid Accounts"})
        evidence.append("A successful login from an unusual location was observed.")
        risk_level = "high"
        confidence += 0.1

    return {
        "summary": "The incident is consistent with credential phishing followed by suspicious cloud account access. The attempted forwarding rule increases the likelihood of account compromise.",
        "incident_type": incident_type,
        "risk_level": risk_level,
        "confidence": min(round(confidence, 2), 0.9),
        "iocs": iocs,
        "attack_patterns": attack_patterns or ["Unknown"],
        "mitre_attack": mitre,
        "evidence": evidence,
        "recommended_actions": [
            "Disable or temporarily lock the affected account.",
            "Revoke active sessions and refresh tokens.",
            "Reset password and require MFA re-registration if needed.",
            "Remove suspicious mailbox forwarding rules.",
            "Review login logs for related IPs, accounts, and time windows.",
            "Preserve logs and phishing message content for follow-up analysis.",
        ],
        "limitations": [
            "Offline mode uses simple heuristics and should not be treated as final analysis.",
            "Indicators use synthetic sample data and should be validated before operational use.",
        ],
    }


def build_prompt(incident: dict[str, Any]) -> list[dict[str, str]]:
    schema = {
        "summary": "short analyst-facing summary",
        "incident_type": "likely incident type",
        "risk_level": "low | medium | high | critical",
        "confidence": "number between 0 and 1",
        "iocs": [{"type": "ip|domain|url|email|hash|other", "value": "indicator", "why_relevant": "short reason"}],
        "attack_patterns": ["observed or likely attack pattern"],
        "mitre_attack": [{"technique": "Txxxx if known", "name": "technique name", "reason": "short reason"}],
        "evidence": ["specific evidence from the incident input"],
        "recommended_actions": ["ordered response action"],
        "limitations": ["uncertainty or missing data"],
    }
    system = (
        "You are a security analyst assistant. Return only valid JSON. "
        "Do not include markdown. Do not invent indicators. "
        "Every conclusion must be supported by evidence from the input. "
        "If information is missing, state it in limitations."
    )
    user = (
        "Triage this security incident and return JSON matching this schema:\n"
        f"{json.dumps(schema, indent=2)}\n\n"
        "Incident input:\n"
        f"{incident_to_text(incident)}"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_llm(
    incident: dict[str, Any],
    api_key: str,
    base_url: str,
    model: str,
    timeout: int,
) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": build_prompt(incident),
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM API HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM API connection error: {exc}") from exc

    data = json.loads(raw)
    content = data["choices"][0]["message"]["content"]
    result = json.loads(content)
    if not isinstance(result, dict):
        raise ValueError("LLM returned JSON, but not a JSON object.")
    return result


def validate_result(result: dict[str, Any]) -> list[str]:
    errors = []
    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in result:
            errors.append(f"Missing required field: {field}")
            continue
        if not isinstance(result[field], expected_type):
            errors.append(f"Field {field} has wrong type: expected {expected_type}")
    confidence = result.get("confidence")
    if isinstance(confidence, (int, float)) and not 0 <= confidence <= 1:
        errors.append("Field confidence must be between 0 and 1.")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-assisted security incident triage")
    parser.add_argument("--input", required=True, type=Path, help="Path to incident JSON input")
    parser.add_argument("--output", required=True, type=Path, help="Path to write triage JSON output")
    parser.add_argument("--offline", action="store_true", help="Use local heuristic mode without an API call")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", DEFAULT_MODEL), help="LLM model name")
    parser.add_argument(
        "--base-url",
        default=os.getenv("LLM_API_BASE_URL", DEFAULT_BASE_URL),
        help="OpenAI-compatible API base URL",
    )
    parser.add_argument("--timeout", default=60, type=int, help="API timeout in seconds")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    incident = load_json(args.input)

    if args.offline:
        result = offline_triage(incident)
    else:
        api_key = os.getenv("GROQ_API_KEY") or os.getenv("LLM_API_KEY")
        if not api_key:
            print("Missing GROQ_API_KEY or LLM_API_KEY. Use --offline or set an API key.", file=sys.stderr)
            return 2
        result = call_llm(incident, api_key, args.base_url, args.model, args.timeout)

    errors = validate_result(result)
    if errors:
        result["_schema_warnings"] = errors

    save_json(args.output, result)
    print(f"Wrote triage report to {args.output}")
    if errors:
        print("Schema warnings:", "; ".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
