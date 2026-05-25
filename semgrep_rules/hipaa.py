"""
Semgrep test fixtures for HIPAA rules.
Run with: semgrep --test semgrep_rules/
"""
import hashlib
import logging

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HIPAA-001: PHI in log statements
# ---------------------------------------------------------------------------

def log_violation(patient_id):
    # ruleid: hipaa-phi-in-logs
    logging.info("Processing patient", patient_id)


def log_clean():
    request_id = "req-999"
    # ok: hipaa-phi-in-logs
    logging.info("Processing request", request_id)


def log_fstring_violation(patient_id):
    # ruleid: hipaa-phi-in-logs
    logging.warning(f"Record fetched: {patient_id}")


def log_fstring_clean():
    request_id = "req-999"
    # ok: hipaa-phi-in-logs
    logging.warning(f"Request handled: {request_id}")


def print_phi_violation(mrn):
    # ruleid: hipaa-phi-in-logs
    print(f"Debug: {mrn}")


def print_phi_clean():
    request_id = "req-999"
    # ok: hipaa-phi-in-logs
    print(f"Debug: {request_id}")


# ---------------------------------------------------------------------------
# HIPAA-002: PHI in exception messages
# ---------------------------------------------------------------------------

def exception_violation(patient_id):
    # ruleid: hipaa-phi-in-exceptions
    raise ValueError("Lookup failed", patient_id)


def exception_clean():
    request_id = "req-999"
    # ok: hipaa-phi-in-exceptions
    raise ValueError("Lookup failed", request_id)


def exception_fstring_violation(mrn):
    # ruleid: hipaa-phi-in-exceptions
    raise RuntimeError(f"Cannot process {mrn}")


def exception_fstring_clean():
    request_id = "req-999"
    # ok: hipaa-phi-in-exceptions
    raise RuntimeError(f"Cannot process {request_id}")


# ---------------------------------------------------------------------------
# HIPAA-003: Hardcoded PHI values
# ---------------------------------------------------------------------------

def hardcoded_phi_violation():
    # ruleid: hipaa-hardcoded-phi
    patient_ssn = "123-45-6789"
    return patient_ssn


def hardcoded_phi_clean():
    # ok: hipaa-hardcoded-phi
    service_name = "auth-service"
    return service_name


# ---------------------------------------------------------------------------
# HIPAA-004: PHI written to file without encryption
# ---------------------------------------------------------------------------

def file_write_violation(patient_data):
    with open("output.txt", "wb") as f:
        # ruleid: hipaa-unencrypted-phi-write
        f.write(patient_data)


def file_write_clean():
    report = "summary"
    with open("report.txt", "w") as f:
        # ok: hipaa-unencrypted-phi-write
        f.write(report)


# ---------------------------------------------------------------------------
# HIPAA-005: Unencrypted HTTP transmission
# ---------------------------------------------------------------------------

def http_violation():
    # ruleid: hipaa-http-phi-transmission
    requests.get("http://internal-api.example.com/records")


def http_clean():
    # ok: hipaa-http-phi-transmission
    requests.get("https://internal-api.example.com/records")


def http_post_violation():
    # ruleid: hipaa-http-phi-transmission
    requests.post("http://api.example.com/patients", json={})


def http_post_clean():
    # ok: hipaa-http-phi-transmission
    requests.post("https://api.example.com/patients", json={})


# ---------------------------------------------------------------------------
# HIPAA-006: Weak cryptography on PHI
# ---------------------------------------------------------------------------

def weak_crypto_violation(patient_id):
    # ruleid: hipaa-weak-crypto-phi
    h = hashlib.md5(patient_id)
    return h


def weak_crypto_clean():
    file_content = b"data"
    # ok: hipaa-weak-crypto-phi
    h = hashlib.md5(file_content)
    return h


def weak_sha1_violation(mrn):
    # ruleid: hipaa-weak-crypto-phi
    h = hashlib.sha1(mrn)
    return h


# ---------------------------------------------------------------------------
# HIPAA-007: PHI in URL query parameters
# ---------------------------------------------------------------------------

def url_params_violation():
    # ruleid: hipaa-phi-in-url
    requests.get("https://api.example.com/records", params={"patient_id": "12345"})


def url_params_clean():
    # ok: hipaa-phi-in-url
    requests.get("https://api.example.com/search", params={"query": "active"})


# ---------------------------------------------------------------------------
# HIPAA-008: PHI in code comments
# annotation goes on the line BEFORE the matching comment for pattern-regex rules
# ---------------------------------------------------------------------------

# ruleid: hipaa-phi-in-comments
# patient_id: P-12345

# ok: hipaa-phi-in-comments
# user_id: U-00001

# ruleid: hipaa-phi-in-comments
# mrn: MRN-99887


# ---------------------------------------------------------------------------
# HIPAA-009: SQL injection with PHI
# ---------------------------------------------------------------------------

def sql_injection_violation(db, patient_id):
    # ruleid: hipaa-sql-injection-phi
    db.execute(f"SELECT * FROM records WHERE id = {patient_id}")


def sql_injection_clean(db, patient_id):
    # ok: hipaa-sql-injection-phi
    db.execute("SELECT * FROM records WHERE id = %s", (patient_id,))


def sql_format_violation(db, mrn):
    # ruleid: hipaa-sql-injection-phi
    db.execute("SELECT * FROM records WHERE mrn = %s" % mrn)


# ---------------------------------------------------------------------------
# HIPAA-010: PHI stored in cookies
# ---------------------------------------------------------------------------

def cookie_violation(response, patient_ssn):
    # ruleid: hipaa-phi-in-cookie
    response.set_cookie("data", patient_ssn)


def cookie_clean(response):
    session_token = "tok_abc123"
    # ok: hipaa-phi-in-cookie
    response.set_cookie("session", session_token)
