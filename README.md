# AI-Assisted Security Incident Triage

This project is a cybersecurity portfolio tool that uses an LLM API to assist with early-stage security incident triage.

The goal is not to let an LLM make final security decisions. The goal is to help an analyst structure messy incident notes into a reviewable triage report: indicators, attack patterns, likely incident type, risk level, MITRE ATT&CK mapping, evidence, and recommended response actions.

## Research Relevance

This project is designed as a small portfolio prototype for AI-assisted security incident analysis. Instead of using an LLM as a final decision maker, it uses the model to transform messy incident notes, suspicious login descriptions, URLs, logs, and threat reports into structured triage output for analyst review. The output includes indicators of compromise, likely attack patterns, MITRE ATT&CK mapping, evidence, confidence, limitations, and recommended response actions.

This makes the project relevant to AI-assisted cybersecurity investigation and threat intelligence analysis because it focuses on identifying attack patterns and improving incident response workflows, rather than simply generating free-form chatbot advice. For Waseda IPS / Jun Wu's Network Intelligence and Security Lab, the project is positioned as an initial implementation of AI-assisted analysis for network security incidents and attack pattern identification. Future extensions could compare offline rules with LLM-assisted triage, evaluate repeated incident samples, and add more network or authentication log inputs.

For Waseda IPS / Wu Lab, this project is positioned as:

```text
AI-assisted analysis for network security incidents and attack pattern identification.
```

## Features

- Accepts a JSON incident input file.
- Extracts candidate indicators of compromise.
- Uses an LLM API for structured incident triage.
- Supports Groq or other OpenAI-compatible chat completion APIs.
- Produces JSON output for analyst review.
- Includes an offline mode so the project can run without an API key.
- Avoids storing API keys in source code.
- Defines a defensive security scope for authorized offline analysis.

## Example Use Cases

- Suspicious login investigation.
- Credential phishing triage.
- Cloud account compromise notes.
- Network security incident summaries.
- Threat intelligence brief preparation.

## Setup

Use Python 3.10+.

No external Python packages are required.

Copy the environment template:

```bash
cp .env.example .env
```

Then set a new API key in your shell. Do not commit `.env`.

```bash
export GROQ_API_KEY="your_new_key_here"
```

The key should look like a Groq API key. If you previously pasted a key into a chat, rotate or revoke that key and create a new one.

## Run Offline Mode

Offline mode does not call the LLM API. It uses local regex extraction and simple heuristic classification.

```bash
python3 src/triage.py --input data/sample_incident.json --offline --output reports/sample_triage.json
```

## Run With Groq API

```bash
export GROQ_API_KEY="your_new_key_here"
python3 src/triage.py --input data/sample_incident.json --output reports/sample_triage.json
```

Optional model override:

```bash
python3 src/triage.py --input data/sample_incident.json --model llama-3.3-70b-versatile
```

## Output Schema

The output is JSON with these fields:

- `summary`
- `incident_type`
- `risk_level`
- `confidence`
- `iocs`
- `attack_patterns`
- `mitre_attack`
- `evidence`
- `recommended_actions`
- `limitations`

## Repository Structure

```text
ai-assisted-security-incident-triage/
├── README.md
├── .env.example
├── .gitignore
├── data/
│   └── sample_incident.json
├── docs/
│   ├── scope-and-ethics.md
│   └── waseda-fit.md
├── reports/
│   └── .gitkeep
├── src/
│   └── triage.py
└── tests/
    └── test_offline_triage.py
```

## Analyst Safety Note

LLM output must be reviewed by a human analyst. The tool asks the model to provide evidence and confidence, but it can still miss indicators, overstate risk, or produce incorrect ATT&CK mappings.

This project is limited to authorized defensive security work and offline analysis of user-provided incident data. See [Scope and Ethics](docs/scope-and-ethics.md).
