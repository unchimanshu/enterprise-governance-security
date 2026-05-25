"""
PolicyGuard admin UI.
Run with: uvicorn ui.app:app --reload
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

load_dotenv()

app = FastAPI(title="PolicyGuard")

_UI_DIR = Path(__file__).parent
_POLICIES_DIR = _UI_DIR.parent / "policies"
_PENDING_RULES_FILE = _POLICIES_DIR / "pending_rules.json"
templates = Jinja2Templates(directory=str(_UI_DIR / "templates"))

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

VENDOR_CATALOG = [
    {
        "id": "hipaa",
        "name": "HIPAA",
        "full_name": "Health Insurance Portability and Accountability Act",
        "description": "Technical safeguards for protecting electronic PHI (ePHI). Covers audit controls, access control, transmission security, and encryption at rest.",
        "tags": ["Healthcare", "Privacy", "PHI", "US Federal"],
        "rule_count": 10,
        "framework_key": "HIPAA",
        "category": "Healthcare & Privacy",
    },
    {
        "id": "secrets",
        "name": "Secrets & Credentials",
        "full_name": "Hardcoded Secrets Detection",
        "description": "Detects hardcoded API keys, tokens, passwords, and database credentials committed to source code before they reach production.",
        "tags": ["Security", "DevSecOps", "Credentials"],
        "rule_count": 10,
        "framework_key": "Secrets",
        "category": "Security Hygiene",
    },
    {
        "id": "pci-dss",
        "name": "PCI-DSS v4.0",
        "full_name": "Payment Card Industry Data Security Standard",
        "description": "Security controls for systems that store, process, or transmit cardholder data and sensitive authentication data.",
        "tags": ["Payments", "Finance", "Cardholder Data"],
        "rule_count": None,
        "framework_key": None,
        "category": "Financial Services",
        "coming_soon": True,
    },
    {
        "id": "soc2",
        "name": "SOC 2 Type II",
        "full_name": "Service Organization Control 2",
        "description": "Trust service criteria covering security, availability, processing integrity, confidentiality, and privacy. Required by most enterprise buyers.",
        "tags": ["SaaS", "Enterprise", "Audit"],
        "rule_count": None,
        "framework_key": None,
        "category": "Audit & Compliance",
        "coming_soon": True,
    },
    {
        "id": "gdpr",
        "name": "GDPR",
        "full_name": "General Data Protection Regulation",
        "description": "EU regulation on data protection and privacy. Required for any organization handling personal data of EU residents.",
        "tags": ["EU", "Privacy", "PII"],
        "rule_count": None,
        "framework_key": None,
        "category": "Privacy",
        "coming_soon": True,
    },
    {
        "id": "nist-csf",
        "name": "NIST CSF 2.0",
        "full_name": "NIST Cybersecurity Framework",
        "description": "Framework for improving critical infrastructure cybersecurity. Widely adopted for federal and enterprise security programs.",
        "tags": ["Government", "Infrastructure", "Federal"],
        "rule_count": None,
        "framework_key": None,
        "category": "Government & Federal",
        "coming_soon": True,
    },
]

ASSISTANT_STARTERS = [
    "What frameworks should we add for a healthcare startup?",
    "We're expanding to Europe — what compliance do we need?",
    "What if we start handling credit card payments?",
    "Explain what HIPAA-001 checks and why it matters.",
    "Summarize all active rules by severity.",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_all_rules() -> list[dict]:
    rules: list[dict] = []
    for json_file in sorted(_POLICIES_DIR.glob("*.json")):
        data = json.loads(json_file.read_text())
        if "rules" not in data:
            continue
        framework = data.get("framework", json_file.stem)
        for rule in data["rules"]:
            rules.append({**rule, "framework": framework})
    return rules


def active_framework_keys() -> set[str]:
    return {r["framework"] for r in load_all_rules()}


def get_openai_client():
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    from openai import OpenAI
    return OpenAI(api_key=api_key)


def load_pending_rules() -> dict:
    if not _PENDING_RULES_FILE.exists():
        return {"last_synced": None, "incidents": []}
    return json.loads(_PENDING_RULES_FILE.read_text())


def save_pending_rules(data: dict) -> None:
    _PENDING_RULES_FILE.write_text(json.dumps(data, indent=2))


def get_pending_count() -> int:
    try:
        return sum(1 for i in load_pending_rules()["incidents"] if i["status"] == "pending")
    except Exception:
        return 0


templates.env.globals["get_pending_count"] = get_pending_count


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    rules = load_all_rules()
    by_severity: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    by_framework: dict[str, int] = defaultdict(int)
    for r in rules:
        by_severity[r["severity"]] += 1
        by_category[r["category"]] += 1
        by_framework[r["framework"]] += 1
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "total_rules": len(rules),
        "by_severity": dict(by_severity),
        "by_category": sorted(by_category.items(), key=lambda x: -x[1]),
        "by_framework": dict(by_framework),
        "active_page": "dashboard",
    })


# ── Policy library ─────────────────────────────────────────────────────────────

@app.get("/policies", response_class=HTMLResponse)
def policies(request: Request, framework: str = "HIPAA"):
    all_rules = load_all_rules()
    frameworks = sorted({r["framework"] for r in all_rules})
    filtered = sorted(
        [r for r in all_rules if r["framework"] == framework],
        key=lambda r: SEVERITY_ORDER.get(r["severity"], 9),
    )
    return templates.TemplateResponse("policies.html", {
        "request": request,
        "rules": filtered,
        "frameworks": frameworks,
        "current_framework": framework,
        "active_page": "policies",
    })


@app.get("/policies/{rule_id}", response_class=HTMLResponse)
def policy_detail(request: Request, rule_id: str):
    all_rules = load_all_rules()
    rule = next((r for r in all_rules if r["rule_id"] == rule_id), None)
    if rule is None:
        return HTMLResponse("Rule not found", status_code=404)
    return templates.TemplateResponse("policy_detail.html", {
        "request": request,
        "rule": rule,
        "active_page": "policies",
    })


# ── Catalog ───────────────────────────────────────────────────────────────────

@app.get("/catalog", response_class=HTMLResponse)
def catalog(request: Request):
    active = active_framework_keys()
    enriched = [{**e, "is_active": e.get("framework_key") in active} for e in VENDOR_CATALOG]
    return templates.TemplateResponse("catalog.html", {
        "request": request,
        "catalog": enriched,
        "active_page": "catalog",
    })


# ── Upload ─────────────────────────────────────────────────────────────────────

@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {
        "request": request,
        "active_page": "catalog",
        "has_openai": bool(os.getenv("OPENAI_API_KEY")),
    })


@app.post("/api/upload/analyze")
async def analyze_upload(
    file: Optional[UploadFile] = File(None),
    text: str = Form(""),
):
    raw_text = ""

    if file and file.filename:
        content = await file.read()
        fname = (file.filename or "").lower()

        if fname.endswith((".txt", ".md")):
            raw_text = content.decode("utf-8", errors="replace")
        elif fname.endswith(".pdf"):
            try:
                import io
                import pdfplumber
                with pdfplumber.open(io.BytesIO(content)) as pdf:
                    raw_text = "\n".join(p.extract_text() or "" for p in pdf.pages)
            except ImportError:
                return JSONResponse(
                    {"error": "PDF support requires pdfplumber. Run: pip install pdfplumber"},
                    status_code=422,
                )
        elif fname.endswith(".docx"):
            try:
                import io
                import docx
                doc = docx.Document(io.BytesIO(content))
                raw_text = "\n".join(p.text for p in doc.paragraphs)
            except ImportError:
                return JSONResponse(
                    {"error": "DOCX support requires python-docx. Run: pip install python-docx"},
                    status_code=422,
                )
        else:
            return JSONResponse(
                {"error": "Unsupported file type. Upload a .txt, .md, .pdf, or .docx file."},
                status_code=422,
            )
    elif text.strip():
        raw_text = text.strip()
    else:
        return JSONResponse({"error": "Provide a file or paste policy text."}, status_code=422)

    if len(raw_text) < 50:
        return JSONResponse({"error": "Document too short to extract meaningful rules."}, status_code=422)

    client = get_openai_client()
    if client is None:
        return JSONResponse({"error": "OPENAI_API_KEY not configured."}, status_code=503)

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            response_format={"type": "json_object"},
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a compliance rule extraction engine. Given a policy document, extract concrete "
                        "enforceable code-level rules that a static analysis tool could check. Focus only on rules "
                        "that apply to source code — not process or organizational policies. "
                        "Return JSON with key 'rules' containing an array of objects, each with: "
                        "rule_id (string, e.g. CUSTOM-001), category (string), severity ('high'|'medium'|'low'), "
                        "description (what the rule checks, 1-2 sentences), "
                        "developer_message (actionable fix guidance, 1-2 sentences). "
                        "Generate between 3 and 10 rules. If no code-level rules are extractable, return {\"rules\": []}."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Extract enforceable code-level rules from this policy document:\n\n{raw_text[:8000]}",
                },
            ],
        )
        result = json.loads(response.choices[0].message.content)
        return JSONResponse({"rules": result.get("rules", [])})
    except Exception as exc:
        return JSONResponse({"error": f"AI extraction failed: {exc}"}, status_code=500)


@app.post("/api/upload/approve")
async def approve_rules(request: Request):
    data = await request.json()
    rules: list[dict] = data.get("rules", [])
    if not rules:
        return JSONResponse({"error": "No rules to approve."}, status_code=422)

    custom_file = _POLICIES_DIR / "custom_rules.json"
    if custom_file.exists():
        existing = json.loads(custom_file.read_text())
    else:
        existing = {
            "framework": "Custom",
            "version": "1.0",
            "description": "Custom rules uploaded and approved by admin.",
            "rules": [],
        }

    used_ids = {r["rule_id"] for r in existing["rules"]}
    counter = len(existing["rules"]) + 1
    for rule in rules:
        if not rule.get("rule_id") or rule["rule_id"] in used_ids:
            rule["rule_id"] = f"CUSTOM-{counter:03d}"
            counter += 1
        rule.setdefault("hipaa_reference", "N/A")
        rule.setdefault("semgrep_rule_id", None)
        existing["rules"].append(rule)

    custom_file.write_text(json.dumps(existing, indent=2))
    return JSONResponse({"provisioned": len(rules)})


# ── AI Assistant ───────────────────────────────────────────────────────────────

@app.get("/assistant", response_class=HTMLResponse)
def assistant_page(request: Request):
    rules = load_all_rules()
    return templates.TemplateResponse("assistant.html", {
        "request": request,
        "active_page": "assistant",
        "rule_count": len(rules),
        "has_openai": bool(os.getenv("OPENAI_API_KEY")),
        "starters": ASSISTANT_STARTERS,
    })


@app.post("/api/assistant/chat")
async def chat(request: Request):
    data = await request.json()
    messages: list[dict] = data.get("messages", [])
    if not messages:
        return JSONResponse({"error": "No messages provided."}, status_code=422)

    client = get_openai_client()
    if client is None:
        return JSONResponse(
            {"error": "OPENAI_API_KEY not configured. Add it to your .env file."},
            status_code=503,
        )

    all_rules = load_all_rules()
    rules_context = "\n".join(
        f"  - {r['rule_id']} [{r['framework']}] ({r['severity'].upper()}): {r['description'][:120]}"
        for r in all_rules
    )

    system_prompt = f"""You are PolicyGuard's AI compliance advisor. You help security admins configure, understand, and improve their code-level compliance enforcement.

Currently active rules ({len(all_rules)} total):
{rules_context}

You can:
- Recommend which compliance frameworks to adopt based on the org's industry and data types handled
- Explain what specific rules enforce and the risk they address
- Suggest custom policy language the admin can upload via the document upload feature
- Answer questions about HIPAA, PCI-DSS, SOC 2, GDPR, NIST CSF, and secrets management
- Help interpret a rule violation and explain how a developer should fix it

Be concise and actionable. Use markdown. When recommending frameworks, explain the business risk driving the recommendation."""

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "system", "content": system_prompt}] + messages,
            temperature=0.3,
            max_tokens=900,
        )
        return JSONResponse({"message": response.choices[0].message.content})
    except Exception as exc:
        return JSONResponse({"error": f"AI request failed: {exc}"}, status_code=500)


# ── Threat Intelligence / Incidents ───────────────────────────────────────────

@app.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request):
    data = load_pending_rules()
    all_incidents = data.get("incidents", [])
    pending = [i for i in all_incidents if i["status"] == "pending"]
    history = sorted(
        [i for i in all_incidents if i["status"] != "pending"],
        key=lambda x: x.get("reviewed_at", ""),
        reverse=True,
    )
    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "active_page": "incidents",
        "pending": pending,
        "history": history,
        "last_synced": data.get("last_synced"),
        "pending_count": len(pending),
    })


@app.post("/api/incidents/fetch")
async def fetch_incidents():
    from src.threat_intel import (
        scan_stack, fetch_cisa_kev, match_against_stack,
        generate_proposed_rule, send_incident_alert,
    )

    client = get_openai_client()
    if client is None:
        return JSONResponse({"error": "OPENAI_API_KEY not configured."}, status_code=503)

    try:
        stack = scan_stack()
        kev_entries = fetch_cisa_kev()
        matches = match_against_stack(kev_entries, stack)
    except Exception as exc:
        return JSONResponse({"error": f"Failed to fetch threat data: {exc}"}, status_code=500)

    data = load_pending_rules()
    existing_cves = {i["cve_id"] for i in data["incidents"]}

    new_incidents: list[dict] = []
    counter = len(data["incidents"]) + 1

    for entry in matches:
        cve_id = entry.get("cveID", "")
        if cve_id in existing_cves:
            continue

        rule_id = f"INC-{counter:03d}"
        try:
            proposed_rule = generate_proposed_rule(entry, client, rule_id)
        except Exception:
            proposed_rule = {
                "rule_id": rule_id,
                "category": "Vulnerable Dependency",
                "severity": "medium",
                "description": f"Detected use of vulnerable package: {entry.get('product', 'unknown')}.",
                "developer_message": f"See {cve_id} for remediation guidance.",
                "hipaa_reference": "N/A",
                "semgrep_rule_id": None,
            }

        incident: dict = {
            "id": f"inc-{cve_id.lower()}",
            "cve_id": cve_id,
            "source": "cisa_kev",
            "title": entry.get("vulnerabilityName", cve_id),
            "description": entry.get("shortDescription", ""),
            "affected_package": entry.get("product", ""),
            "matched_package": entry.get("_matched_package", ""),
            "severity": "high" if entry.get("knownRansomwareCampaignUse") == "Known" else "medium",
            "published_date": entry.get("dateAdded", ""),
            "proposed_rule": proposed_rule,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        data["incidents"].append(incident)
        new_incidents.append(incident)
        existing_cves.add(cve_id)
        counter += 1

    data["last_synced"] = datetime.now(timezone.utc).isoformat()
    save_pending_rules(data)

    if new_incidents:
        to_email = os.getenv("ALERT_EMAIL", "")
        from_email = os.getenv("SMTP_FROM", "")
        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_password = os.getenv("SMTP_PASSWORD", "")
        if all([to_email, from_email, smtp_host, smtp_user, smtp_password]):
            try:
                send_incident_alert(
                    new_incidents, to_email, from_email,
                    smtp_host, smtp_port, smtp_user, smtp_password,
                )
            except Exception:
                pass

    return JSONResponse({"new_incidents": len(new_incidents), "total_matched": len(matches)})


@app.post("/api/incidents/{inc_id}/approve")
async def approve_incident(inc_id: str, request: Request):
    body = await request.json()
    blocking = body.get("blocking", False)

    data = load_pending_rules()
    incident = next((i for i in data["incidents"] if i["id"] == inc_id), None)
    if incident is None:
        return JSONResponse({"error": "Incident not found."}, status_code=404)
    if incident["status"] != "pending":
        return JSONResponse({"error": "Incident already reviewed."}, status_code=409)

    rule = {**incident["proposed_rule"]}
    if blocking:
        rule["severity"] = "high"
        incident["status"] = "approved_blocking"
    else:
        rule["severity"] = "medium"
        incident["status"] = "approved"

    incident["reviewed_at"] = datetime.now(timezone.utc).isoformat()

    custom_file = _POLICIES_DIR / "custom_rules.json"
    if custom_file.exists():
        existing = json.loads(custom_file.read_text())
    else:
        existing = {
            "framework": "Custom",
            "version": "1.0",
            "description": "Custom rules uploaded and approved by admin.",
            "rules": [],
        }

    used_ids = {r["rule_id"] for r in existing["rules"]}
    if rule["rule_id"] in used_ids:
        rule["rule_id"] = f"INC-{inc_id[-3:]}-AUTO"
    existing["rules"].append(rule)
    custom_file.write_text(json.dumps(existing, indent=2))
    save_pending_rules(data)

    return JSONResponse({"approved": inc_id, "severity": rule["severity"]})


@app.post("/api/incidents/{inc_id}/reject")
async def reject_incident(inc_id: str, request: Request):
    body = await request.json()
    reason = body.get("reason", "")

    data = load_pending_rules()
    incident = next((i for i in data["incidents"] if i["id"] == inc_id), None)
    if incident is None:
        return JSONResponse({"error": "Incident not found."}, status_code=404)
    if incident["status"] != "pending":
        return JSONResponse({"error": "Incident already reviewed."}, status_code=409)

    incident["status"] = "rejected"
    incident["reject_reason"] = reason
    incident["reviewed_at"] = datetime.now(timezone.utc).isoformat()
    save_pending_rules(data)

    return JSONResponse({"rejected": inc_id})
