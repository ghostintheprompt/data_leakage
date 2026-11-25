from __future__ import annotations

import base64
from collections import defaultdict
from flask import Flask, Response, jsonify, render_template, request
import hashlib
import hmac
import json
import os
import random
import re
import requests
import time

app = Flask(__name__, template_folder='templates')

USE_STEALTH_PROXY = False
REQUIRE_SIGNED_SESSION = False
ENFORCE_ACCOUNT_SESSION_BINDING = False  
ENABLE_EDGE_RATE_LIMIT = False
HEADER_ONLY_TOKEN_FORWARDING = False
MASK_TRAJECTORY_PATHS = False
ENCRYPT_PAYLOADS = False
DISABLE_THIRD_PARTY_IN_STAGING = False
ENVIRONMENT = os.environ.get("APP_ENV", "staging")

SINK_BASE = os.environ.get("SINK_BASE", "http://127.0.0.1:5000")
LOCAL_LOG_PATH = os.environ.get("LOCAL_STEALTH_LOG", "local_stealth_telemetry.jsonl")

TOKEN_REVOCATION_LIST = set()
SERVER_CLIENT_TOKEN = os.environ.get("DD_CLIENT_TOKEN", "pub_placeholder_token_abc123xyz789")
SIGNING_SECRET = os.environ.get("SESSION_SIGNING_SECRET", "enterprise-ephemeral-hmac-secret").encode()

RATE_BUCKETS = defaultdict(list)
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW_SEC = 10
SIGNATURE_TTL_SEC = 60

ACTIVE_SESSION_ACCOUNTS = {
    "sess_alpha_0001": "acct_internal_authorized_88",
}

def generate_session_sig(session_id: str, account_id: str, timestamp: str) -> str:
    msg = (
        f"{session_id}:{account_id}:{timestamp}".encode()
        if ENFORCE_ACCOUNT_SESSION_BINDING
        else f"{session_id}:{timestamp}".encode()
    )
    return hmac.new(SIGNING_SECRET, msg, hashlib.sha256).hexdigest()

def verify_session_sig(session_id: str, account_id: str, timestamp: str, provided_sig: str) -> tuple[bool, str]:
    if session_id in TOKEN_REVOCATION_LIST:
        return False, "Revoked Token Context: Tripwire Canary Tripped"
    if not session_id or not timestamp or not provided_sig:
        return False, "Missing session signature headers"
    try:
        ts_val = int(timestamp)
    except ValueError:
        return False, "Malformed session timestamp"
    if abs(int(time.time()) - ts_val) > SIGNATURE_TTL_SEC:
        return False, "Expired ephemeral session token"
    if ENFORCE_ACCOUNT_SESSION_BINDING:
        expected_acct = ACTIVE_SESSION_ACCOUNTS.get(session_id)
        if not expected_acct or expected_acct != account_id:
            return False, "Session-to-Account binding mismatch"
    expected = generate_session_sig(session_id, account_id, timestamp)
    if not hmac.compare_digest(provided_sig, expected):
        return False, "Invalid HMAC session signature"
    return True, "ok"

def opaque_id(raw_id: str, prefix: str = "id") -> str:
    digest = hmac.new(SIGNING_SECRET, raw_id.encode(), hashlib.sha256).hexdigest()[:10]
    return f"{prefix}_{digest}"

def is_rate_limited(client_key: str) -> bool:
    now = time.time()
    recent = [ts for ts in RATE_BUCKETS[client_key] if now - ts < RATE_LIMIT_WINDOW_SEC]
    recent.append(now)
    RATE_BUCKETS[client_key] = recent
    return len(recent) > RATE_LIMIT_MAX

def scrub_text(val: str) -> str:
    val = re.sub(r"project-stealth(-alpha)?", "production-web", val, flags=re.IGNORECASE)
    val = re.sub(r"stealth(-eval-v2)?", "internal-eval", val, flags=re.IGNORECASE)
    val = re.sub(r"/workflows/flow_[a-z0-9_]+", "/v1/wf/[REDACTED]", val, flags=re.IGNORECASE)
    val = re.sub(r"camp_[a-z0-9_]+", "camp_[REDACTED]", val, flags=re.IGNORECASE)
    val = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]", val)
    val = re.sub(r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "[REDACTED_INTERNAL_IP]", val)
    return val

SENSITIVE_CONTEXT_KEYS = {"system_prompt", "prompt_template", "tool_calls", "mcp_server", "agent_handoff", "node_transition", "error_stack"}

def scrub_payload(data: dict) -> dict:
    scrubbed = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_CONTEXT_KEYS:
            scrubbed[key] = "[REDACTED_AGENT_CONTEXT]"
        elif isinstance(value, str):
            scrubbed[key] = scrub_text(value)
        elif isinstance(value, dict):
            scrubbed[key] = scrub_payload(value)
        else:
            scrubbed[key] = value
    if "service" in scrubbed:
        scrubbed["service"] = "enterprise-app-prod"
    if "version" in scrubbed:
        scrubbed["version"] = "1.0.0-redacted"
    if "pageTitle" in scrubbed:
        scrubbed["pageTitle"] = "Secure Workspace Console"
    return scrubbed

def encode_stealth_body(data: dict) -> dict:
    raw = json.dumps(data).encode("utf-8")
    return {"enc_v1": base64.b64encode(raw).decode("ascii")}

@app.route("/")
def index():
    session_id = "sess_alpha_0001"
    account_id = ACTIVE_SESSION_ACCOUNTS[session_id]
    session_ts = str(int(time.time()))
    session_sig = generate_session_sig(session_id, account_id, session_ts)
    rum_enabled = not (DISABLE_THIRD_PARTY_IN_STAGING and ENVIRONMENT == "staging")
    return render_template(
        "index.html",
        use_proxy=USE_STEALTH_PROXY,
        rum_enabled=rum_enabled,
        mask_paths=MASK_TRAJECTORY_PATHS,
        encrypt_payloads=ENCRYPT_PAYLOADS,
        session_id=session_id,
        account_id=account_id,
        session_ts=session_ts,
        session_sig=session_sig,
        sink_base=SINK_BASE,
        client_token="" if USE_STEALTH_PROXY else SERVER_CLIENT_TOKEN,
    )

@app.route("/api/session-token", methods=["GET"])
def get_session_token():
    session_id = "sess_alpha_0001"
    if session_id in TOKEN_REVOCATION_LIST:
        return jsonify({"error": "Revoked Token Context: Tripwire Canary Tripped"}), 403
    account_id = ACTIVE_SESSION_ACCOUNTS[session_id]
    current_ts = str(int(time.time()))
    sig = generate_session_sig(session_id, account_id, current_ts)
    return jsonify({"timestamp": current_ts, "signature": sig})

@app.route("/workflows/<flow_id>", methods=["POST"])
@app.route("/v1/wf/<flow_id>", methods=["POST"])
def run_trajectory(flow_id):
    tokens_used = random.randint(3600, 5200)
    duration_ms = random.randint(1550, 2900)
    response_obj = {
        "workflow_id": opaque_id(flow_id, "wf") if MASK_TRAJECTORY_PATHS else flow_id,
        "masked": MASK_TRAJECTORY_PATHS,
        "status": "completed",
        "tokens_used": tokens_used,
        "duration_ms": duration_ms,
        "execution_mode": "opaque" if MASK_TRAJECTORY_PATHS else "orchestrator-multi-agent-v2",
    }
    if ENCRYPT_PAYLOADS:
        return jsonify(encode_stealth_body(response_obj))
    return jsonify(response_obj)

@app.route("/workflows/<flow_id>/stream", methods=["GET"])
@app.route("/v1/wf/<flow_id>/stream", methods=["GET"])
def stream_trajectory(flow_id):
    steps = (
        [{"step": 1, "state": "running"}, {"step": 2, "state": "done"}]
        if MASK_TRAJECTORY_PATHS
        else [
            {"node_transition": "orchestrator_planner -> mcp_data_lookup", "mcp_server": "internal-vault-mcp"},
            {"node_transition": "mcp_data_lookup -> validation_node", "model_route": "enterprise-eval-v2"},
        ]
    )
    def generate():
        for frame in steps:
            yield f"data: {json.dumps(frame)}\n\n"
    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/flags", methods=["GET"])
def server_side_flags():
    return jsonify({"dark_mode": True, "orchestrator_v2": True, "eval_variant": "production-b"})

@app.route("/api/telemetry", methods=["POST"])
@app.route("/e/", methods=["POST"])
def stealth_proxy():
    if DISABLE_THIRD_PARTY_IN_STAGING and ENVIRONMENT == "staging":
        return jsonify({"status": "disabled", "reason": "Third-party telemetry blocked in staging"}), 200
    if ENABLE_EDGE_RATE_LIMIT:
        rate_key = f"{request.remote_addr or 'unknown'}:{request.headers.get('X-App-Session-ID', 'anon')}"
        if is_rate_limited(rate_key):
            return jsonify({"error": "Rate limit exceeded (Denial-of-Wallet protection)"}), 429
    sess_id = request.headers.get("X-App-Session-ID", "")
    acct_id = request.headers.get("X-Account-Id", "")
    sess_ts = request.headers.get("X-Session-Timestamp", "")
    provided_sig = request.headers.get("X-Session-Signature", "")
    if sess_id in TOKEN_REVOCATION_LIST:
        return jsonify({"error": "Revoked Token Context: Tripwire Canary Tripped"}), 403
    payload = request.get_json(silent=True) or {}
    raw_payload_blob = json.dumps(payload).lower()
    if "decoy_credential" in raw_payload_blob or "vault_root_key" in raw_payload_blob:
        if sess_id:
            TOKEN_REVOCATION_LIST.add(sess_id)
        return jsonify({"error": "Security Boundary Fault: Identity Revoked"}), 403
    if REQUIRE_SIGNED_SESSION:
        ok, reason = verify_session_sig(sess_id, acct_id, sess_ts, provided_sig)
        if not ok:
            return jsonify({"error": reason}), 401
    processed_payload = scrub_payload(payload)
    if ENCRYPT_PAYLOADS:
        processed_payload = encode_stealth_body(processed_payload)
    target_params = {}
    if not HEADER_ONLY_TOKEN_FORWARDING and not request.path.startswith("/e/"):
        target_params["dd-api-key"] = SERVER_CLIENT_TOKEN
    target_headers = {"Content-Type": "application/json", "Origin": "http://127.0.0.1:9000"}
    if HEADER_ONLY_TOKEN_FORWARDING and not request.path.startswith("/e/"):
        target_headers["DD-API-KEY"] = SERVER_CLIENT_TOKEN
    target_url = f"{SINK_BASE}/e/" if request.path.startswith("/e/") else f"{SINK_BASE}/api/v2/rum"
    try:
        response = requests.post(target_url, params=target_params, headers=target_headers, json=processed_payload, timeout=5)
        status_code = response.status_code
    except requests.RequestException as e:
        return jsonify({"error": "Failed to forward telemetry to vendor destination"}), 502
    with open(LOCAL_LOG_PATH, "a") as f:
        f.write(json.dumps({"timestamp": time.time(), "status_forwarded": status_code, "scrubbed": True}) + "\n")
    return jsonify({"status": "proxied", "upstream_code": status_code}), 202

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9000, debug=False)
