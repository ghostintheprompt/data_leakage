from collections import defaultdict
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template_string
import os
import re

app = Flask(__name__)

CAPTURED_LEAKS = []
SIEM_PROXY_LOGS = []
INGEST_COUNTER = defaultdict(int)
CAMPAIGN_TIMESTAMPS = defaultdict(list)

ENFORCE_ORIGIN_LOCK = False
ALLOWED_ORIGINS = [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://localhost:9000",
    "http://127.0.0.1:9000",
    "https://app.targetcorp.local",
]
SIEM_MASK_DD_KEY = False  
ENFORCE_VOLUME_CAP = False  
QUOTA_CAP_EVENTS = 25

VALID_CLIENT_TOKEN = os.environ.get("DD_CLIENT_TOKEN", "pub_placeholder_token_abc123xyz789")

CODENAME_MARKERS = ("stealth", "orchestrator", "multi-agent-planner", "workflows", "camp_")
PII_PATTERNS = (
    (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "EMAIL_PII_EXPOSURE"),
    (r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", "INTERNAL_IP_LEAK"),
    (r"traceback \(most recent call last\)|/srv/app/|at /app/", "STACK_TRACE_PATH_LEAK"),
)
PROMPT_TOOL_MARKERS = ("system_prompt", "tool_calls", "mcp_server", "model_route", "prompt_template")
HANDOFF_MARKERS = ("node_transition", "agent_handoff", "orchestrator_planner", "validation_node", "text/event-stream")


def analyze_cti_indicators(endpoint: str, query_params: dict, headers: dict, payload: dict) -> dict:
    raw_blob = f"{endpoint} {query_params} {headers} {payload}".lower()
    indicators = []

    if "dd-api-key" in query_params:
        indicators.append({
            "type": "QUERY_PARAM_TOKEN_LOG_LEAK",
            "severity": "LOW_INFRA_MEDIUM_LOG",
            "detail": "dd-api-key passed in URI query string; recorded by proxies, browser history, and SIEM logs.",
        })

    for kw in CODENAME_MARKERS:
        if kw in raw_blob:
            indicators.append({
                "type": "PROJECT_METADATA_LEAK",
                "severity": "HIGH_OPSEC",
                "detail": f"Sensitive architectural codename marker '{kw}' captured in outbound analytics telemetry.",
            })
            break

    if re.search(r"flow_[a-z0-9_]+", raw_blob):
        indicators.append({
            "type": "WORKFLOW_ID_EXPOSURE",
            "severity": "MEDIUM_OPSEC",
            "detail": "Predictable /workflows/flow_... structural route identifier captured in public resource hooks.",
        })

    campaign_id = headers.get("X-Campaign-Id") or query_params.get("campaignId", "")
    if campaign_id and "opaque" not in campaign_id.lower() and "redacted" not in campaign_id.lower():
        indicators.append({
            "type": "SESSION_HEADER_CORRELATION",
            "severity": "MEDIUM_OPSEC",
            "detail": f"Unmasked correlation identifier '{campaign_id}' maps ongoing user session to active internal operational campaigns.",
        })

    if campaign_id:
        CAMPAIGN_TIMESTAMPS[campaign_id].append(datetime.now(timezone.utc).isoformat())
        if len(CAMPAIGN_TIMESTAMPS[campaign_id]) >= 3:
            indicators.append({
                "type": "BEHAVIORAL_CAMPAIGN_SPIKE",
                "severity": "MEDIUM_OPSEC",
                "detail": f"Activity surge ({len(CAMPAIGN_TIMESTAMPS[campaign_id])} calls) clustered on correlation identity '{campaign_id}'.",
            })

    resource = payload.get("resource", {}) if isinstance(payload, dict) else {}
    duration_ms = resource.get("duration_ms", 0) if isinstance(resource, dict) else 0
    tokens_used = resource.get("tokens_used", 0) if isinstance(resource, dict) else 0
    if (isinstance(duration_ms, (int, float)) and duration_ms >= 1500) or (
        isinstance(tokens_used, (int, float)) and tokens_used >= 3000
    ):
        indicators.append({
            "type": "AGENT_LATENCY_FINGERPRINT",
            "severity": "MEDIUM_OPSEC",
            "detail": f"High-latency/token footprint ({duration_ms}ms, {tokens_used} tokens) signatures multi-agent workflow runtime.",
        })

    for marker in PROMPT_TOOL_MARKERS:
        if marker in raw_blob:
            indicators.append({
                "type": "ERROR_BOUNDARY_PROMPT_TOOL_LEAK",
                "severity": "HIGH_OPSEC",
                "detail": f"Sub-system runtime error telemetry exposed internal prompt logic '{marker}' context to public targets.",
            })
            break

    for marker in HANDOFF_MARKERS:
        if marker in raw_blob:
            indicators.append({
                "type": "SSE_AGENT_HANDOFF_LEAK",
                "severity": "HIGH_OPSEC",
                "detail": f"Streaming microservice trace metadata ('{marker}') exposed internal logical graph topology over the wire.",
            })
            break

    for pattern, label in PII_PATTERNS:
        if re.search(pattern, raw_blob):
            indicators.append({
                "type": label,
                "severity": "HIGH_OPSEC",
                "detail": f"Unscrubbed data signature or local machine details ({label}) leaked inside payload telemetry frames.",
            })

    opsec_risk = "HIGH" if any(i["severity"] == "HIGH_OPSEC" for i in indicators) else ("MEDIUM" if indicators else "LOW")
    return {
        "opsec_risk": opsec_risk,
        "infra_breach_risk": "LOW (Write-Only Public Client Token)",
        "indicators": indicators,
    }


def record_siem_proxy_log(status_code: int):
    qs = request.query_string.decode("utf-8", errors="ignore")
    if SIEM_MASK_DD_KEY and qs:
        qs = re.sub(r"(dd-api-key=)[^&]+", r"\1[MASKED_BY_SIEM]", qs)
    full_uri = f"{request.path}?{qs}" if qs else request.path
    SIEM_PROXY_LOGS.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": request.method,
        "host": request.host,
        "uri": full_uri,
        "origin": request.headers.get("Origin", "Unknown"),
        "status_code": status_code,
        "token_in_uri": ("dd-api-key=" in full_uri and "[MASKED_BY_SIEM]" not in full_uri),
        "third_party_dns_breadcrumb": True,
    })


@app.route("/api/v1/monitor", methods=["GET"])
@app.route("/api/v1/logs-queries", methods=["GET", "POST"])
@app.route("/api/v1/org", methods=["GET", "PUT"])
def datadog_management_api():
    token = request.headers.get("DD-API-KEY") or request.args.get("dd-api-key", "")
    if token.startswith("pub"):
        return jsonify({
            "errors": [
                "Forbidden: Public Client Tokens (pub...) are write-only for metrics pipelines and cannot read backend stores."
            ]
        }), 403
    return jsonify({"errors": ["Unauthorized: Administrative credentials required."]}), 401


@app.route("/api/v2/rum", methods=["POST"])
@app.route("/api/v2/logs", methods=["POST"])
@app.route("/e/", methods=["POST"])
def ingest_telemetry():
    origin = request.headers.get("Origin", "Unknown")

    if ENFORCE_ORIGIN_LOCK and origin not in ALLOWED_ORIGINS:
        record_siem_proxy_log(403)
        return jsonify({"error": "Origin rejected by API perimeter cross-origin validation policy"}), 403

    token = request.args.get("dd-api-key") or request.headers.get("DD-API-KEY", "")
    if request.path.startswith("/api/v2/") and token != VALID_CLIENT_TOKEN:
        record_siem_proxy_log(401)
        return jsonify({"error": "Invalid client authentication profile token"}), 401

    path_key = request.path
    if ENFORCE_VOLUME_CAP and INGEST_COUNTER[path_key] >= QUOTA_CAP_EVENTS:
        record_siem_proxy_log(429)
        return jsonify({"status": "rejected", "reason": "Operational Ingest Volume Threshold Met"}), 429

    INGEST_COUNTER[path_key] += 1
    payload = request.get_json(silent=True) or {}
    query_params = request.args.to_dict()
    headers = dict(request.headers)

    cti_report = analyze_cti_indicators(request.path, query_params, headers, payload)

    log_entry = {
        "id": len(CAPTURED_LEAKS) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": request.path,
        "cti_analysis": cti_report,
        "raw_payload": payload
    }
    CAPTURED_LEAKS.append(log_entry)
    record_siem_proxy_log(202)

    return jsonify({"status": "accepted", "stored_id": log_entry["id"]}), 202


@app.route("/dashboard", methods=["GET"])
def view_dashboard():
    template = """
    <html>
    <head><title>Operational Telemetry Analysis Console</title></head>
    <body style="font-family:sans-serif; margin:30px; background:#18181c; color:#fff;">
        <h2>Intercepted Telemetry (Perimeter Sinks)</h2>
        <p>Total Anomalies Intercepted: {{ leaks|length }} | Routing Firewall Entries: {{ proxy|length }}</p>
        <hr style="border-color:#2c2c34;"/>
        {% for leak in leaks %}
        <div style="background:#22222a; padding:15px; border-radius:5px; margin-bottom:15px; border-left: 5px solid {{ 'red' if leak.cti_analysis.opsec_risk == 'HIGH' else 'orange' }}">
            <b>Intercepted Record #{{ leak.id }}</b> (OpSec Threat Assessment: {{ leak.cti_analysis.opsec_risk }})<br/>
            Target URI Path: <code>{{ leak.endpoint }}</code><br/>
            <ul>
            {% for indicator in leak.cti_analysis.indicators %}
                <li>[<code>{{ indicator.type }}</code>] - {{ indicator.detail }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </body>
    </html>
    """
    return render_template_string(template, leaks=CAPTURED_LEAKS, proxy=SIEM_PROXY_LOGS)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
