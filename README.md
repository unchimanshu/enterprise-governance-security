# PolicyGuard

**Automated code-level compliance enforcement for engineering teams.**

PolicyGuard runs as a GitHub Actions bot that reviews every pull request against configurable security and compliance frameworks. Violations are flagged before code reaches production — blocking merges on critical issues and warning on others. An admin UI gives security teams full visibility and control over which policies are active.

---

## What it does

### CI/CD Policy Enforcement
Every PR is scanned by Semgrep using rules mapped to compliance frameworks. The bot posts a review comment summarising violations with file locations, severity, and developer fix guidance. High-severity violations block the merge; medium and low are non-blocking warnings.

### Admin UI
A FastAPI web application gives security admins a single pane of glass to:

- **Dashboard** — rule counts by severity and framework, with a live threat alert banner when incidents are pending
- **Policy Library** — browse all active rules, filter by framework, drill into any rule's full detail
- **Catalog** — browse available compliance frameworks and toggle them on or off
- **Document Upload** — paste or upload a policy document (PDF, DOCX, Markdown); GPT-4o extracts enforceable code-level rules which the admin reviews and provisions in one click
- **AI Assistant** — conversational advisor powered by GPT-4o, with all active rules in context; recommends frameworks, explains rules, and helps interpret violations
- **Threat Intelligence — automatically polls the CISA Known Exploited Vulnerabilities (KEV) catalog, matches CVEs against the project's tech stack, and generates proposed enforcement rules for admin review**

### Threat Intelligence Pipeline
1. CISA KEV is polled on demand (or on a schedule)
2. CVEs are fuzzy-matched against packages in `requirements.txt`
3. GPT-4o translates each match into a proposed policy rule
4. The admin reviews each proposal and approves (as a warning or upgraded to blocking) or rejects with a reason
5. Approved rules are immediately active in the Policy Library
6. An email alert is sent when new threats are found (requires SMTP configuration)

---

## Compliance frameworks

| Framework | Status | Rules |
|-----------|--------|-------|
| HIPAA Technical Safeguards | Active | 10 |
| Secrets & Credentials Detection | Active | 10 |
| PCI-DSS v4.0 | Coming soon | — |
| SOC 2 Type II | Coming soon | — |
| GDPR | Coming soon | — |
| NIST CSF 2.0 | Coming soon | — |
| Custom (uploaded) | Active when provisioned | Variable |

---

## Tech stack

- **Python 3.9+**
- **Semgrep** — static analysis engine for policy rules
- **FastAPI + Jinja2** — admin UI (no build step, Tailwind CDN)
- **OpenAI GPT-4o** — rule extraction from policy documents, AI advisor, threat rule generation
- **PyGithub** — PR review comments and CI status checks
- **GitHub Actions** — CI/CD integration

---

## Getting started

### 1. Clone and install

```bash
git clone https://github.com/unchimanshu/enterprise-governance-security.git
cd enterprise-governance-security
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env   # then edit .env
```

Required variables:

```
OPENAI_API_KEY=sk-...          # GPT-4o for AI features
GITHUB_TOKEN=ghp_...           # PR review bot
```

Optional (email alerts for threat intelligence):

```
ALERT_EMAIL=security@yourorg.com
SMTP_FROM=policyguard@yourorg.com
SMTP_HOST=smtp.yourprovider.com
SMTP_PORT=587
SMTP_USER=...
SMTP_PASSWORD=...
```

### 3. Run the admin UI

```bash
uvicorn ui.app:app --reload
```

Open [http://localhost:8000](http://localhost:8000).

### 4. Run the CI/CD bot

```bash
python main.py \
  --repo owner/repo \
  --pr 42 \
  --github-token $GITHUB_TOKEN \
  --openai-key $OPENAI_API_KEY
```

### 5. Run tests

```bash
pytest -v
semgrep --test semgrep_rules/
```

---

## Project structure

```
├── main.py                  # CLI entrypoint for the PR review bot
├── src/
│   ├── models.py            # Pydantic models (ReviewResult, Finding, Severity)
│   ├── rule_loader.py       # Loads policy rules from policies/*.json
│   ├── semgrep_scanner.py   # Runs Semgrep and maps results to findings
│   ├── llm_reviewer.py      # GPT-4o secondary review pass
│   ├── findings_merger.py   # Deduplicates Semgrep + LLM findings
│   ├── github_reporter.py   # Posts PR comments and sets commit status
│   ├── notifier.py          # SMTP email alerts for PR violations
│   └── threat_intel.py      # CISA KEV polling and rule generation
├── policies/
│   ├── hipaa_rules.json     # HIPAA technical safeguard rules
│   ├── secrets_rules.json   # Hardcoded secrets detection rules
│   └── pending_rules.json   # Threat intelligence incident queue
├── semgrep_rules/
│   ├── hipaa.yml            # Semgrep rule definitions for HIPAA
│   ├── secrets.yml          # Semgrep rule definitions for secrets
│   ├── hipaa.py             # Test fixtures for HIPAA rules
│   └── secrets.py           # Test fixtures for secrets rules
├── ui/
│   ├── app.py               # FastAPI application
│   └── templates/           # Jinja2 HTML templates
└── tests/                   # Pytest unit tests
```

---

## Architecture

```
GitHub PR  →  GitHub Actions  →  main.py
                                    │
                          ┌─────────┴──────────┐
                          │                    │
                     Semgrep scan        GPT-4o review
                          │                    │
                          └─────────┬──────────┘
                                    │
                             Merge findings
                                    │
                    ┌───────────────┴──────────────────┐
                    │                                  │
             GitHub PR comment                  Email alert
             (violations + fixes)           (if blocking rules hit)
```

The admin UI runs as a separate FastAPI service and shares the `policies/` directory with the bot.

---

## License

MIT
