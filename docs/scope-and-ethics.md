# Scope and Ethics

This project is designed for defensive security and authorized incident response workflows. It performs offline analysis of user-provided incident data, logs, suspicious activity notes, or sample PCAP-derived summaries. The tool does not capture live traffic from unauthorized networks, intercept credentials, or monitor third-party systems.

The intended use case is SOC triage: helping an analyst organize evidence, identify possible attack patterns, extract indicators, and prepare reviewable incident response recommendations. All findings must be validated by a human analyst before any operational decision is made.

Authorization is required for any data used with this project. Users should only analyze logs, incident records, or network summaries from systems they own, administer, or have explicit permission to investigate.

API keys must be provided through environment variables such as `GROQ_API_KEY`, not stored in source code, documentation, commits, or test data. If an API key is accidentally exposed, it should be revoked or rotated immediately.
