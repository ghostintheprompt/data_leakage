from collections import defaultdict
from datetime import datetime, timezone
import json
import re
import sys

try:
    import requests
except ImportError:
    print("Missing deployment dependency: run 'pip install -r requirements.txt'")
    sys.exit(1)

APP_BASE = "http://localhost:9000"   
SINK_BASE = "http://localhost:5000"  
LAB_CLIENT_TOKEN = "pub_placeholder_token_abc123xyz789"

SDK_INIT_PATTERN = re.compile(r"""(datadogRum\.init|posthog\.init)\s*\(([\s\S]{0,600}?)\)""", re.I)
PROMPT_TOOL_PATTERN = re.compile(
    r"""\b(system_prompt|tool_calls|mcp_server|model_route|node_transition|validation_node)\b""", re.I
)


def phase_1_inspect_local_target():
    print("\n=== PHASE 1: Endpoint Configuration & Stream Inspection ===")
    try:
        html = requests.get(APP_BASE, timeout=5).text
    except requests.RequestException as e:
        print(f"  [!] Target Host Gateway Server Unreachable: {e}")
        return LAB_CLIENT_TOKEN

    tokens = re.findall(r"\bpub_[a-zA-Z0-9_]{10,}\b", html) or re.findall(r"\bpub[a-f0-9]{20,}\b", html)
    has_proxy = "proxyUrl" in html or "/api/telemetry" in html

    print(f"  [*] Client-exposed target token hashes: {tokens or 'None (Secure Proxy Activated)'}")
    print(f"  [*] Backend Proxy Routing Rule Active: {has_proxy}")

    try:
        stream_resp = requests.get(f"{APP_BASE}/workflows/flow_stealth_alpha_99x/stream", timeout=5)
        has_handoff_leak = bool(PROMPT_TOOL_PATTERN.search(stream_resp.text))
        print(f"  [*] SSE Data-Stream Workflow Structural Topology Leak: {has_handoff_leak}")
    except requests.RequestException:
        print("  [!] Failed to query live data-stream pipeline.")

    return tokens[0] if tokens else LAB_CLIENT_TOKEN


def phase_2_verify_write_only_and_siem(token: str):
    print("\n=== PHASE 2: Token Capability Boundary Constraints ===")
    for path in ("/api/v1/monitor", "/api/v1/logs-queries", "/api/v1/org"):
        try:
            r = requests.get(f"{SINK_BASE}{path}", headers={"DD-API-KEY": token}, timeout=5)
            print(f"  [*] Read/Administrative Query Probe {path}: HTTP {r.status_code}")
        except requests.RequestException:
            print(f"  [!] Endpoint path {path} completely untracked.")


def phase_3_flag_and_sink_correlation():
    print("\n=== PHASE 3: Analytical Logging Integration Sync ===")
    try:
        flags = requests.get(f"{APP_BASE}/api/flags", timeout=5).json()
        print(f"  [*] Publicly Discoverable Configuration Flags: {list(flags.keys())}")
    except requests.RequestException:
        print("  [!] Error parsing system status flags.")

    try:
        dashboard_check = requests.get(f"{SINK_BASE}/dashboard", timeout=5)
        print(f"  [*] Analytical Intake Dashboard Management Frame: HTTP {dashboard_check.status_code} (Online)")
    except requests.RequestException:
        print("  [!] Automated ingest telemetry monitoring console offline.")


def phase_4_verify_lab_controls(token: str):
    print("\n=== PHASE 4: Active Perimeter Security Variable Validation ===")
    payload = {"event": "ENTERPRISE_REPLAY_VALIDATION", "service": "perimeter-recon-suite"}

    try:
        r_untrusted = requests.post(
            f"{SINK_BASE}/api/v2/rum?dd-api-key={token}",
            json=payload,
            headers={"Origin": "https://attacker-untrusted-domain.com"},
            timeout=5,
        )
        r_spoofed = requests.post(
            f"{SINK_BASE}/api/v2/rum?dd-api-key={token}",
            json=payload,
            headers={"Origin": "http://localhost:9000"},
            timeout=5,
        )
        print(f"  [*] Ingest Untrusted Cross-Origin Status: HTTP {r_untrusted.status_code} | Matching Origin Status: HTTP {r_spoofed.status_code}")
    except requests.RequestException:
        print("  [!] Core origin validation matrix check dropped.")

    try:
        r_cross_tenant = requests.post(
            f"{APP_BASE}/api/telemetry",
            json=payload,
            headers={
                "X-App-Session-ID": "sess_alpha_0001",
                "X-Account-Id": "acct_malicious_cross_tenant_99",
                "X-Session-Timestamp": str(int(datetime.now(timezone.utc).timestamp())),
                "X-Session-Signature": "forged_hmac_string_fails",
            },
            timeout=5,
        )
        print(f"  [*] Gateway Session-to-Account Binding Validation: HTTP {r_cross_tenant.status_code}")
    except requests.RequestException:
        print("  [!] Gateway cross-tenant validation dropped.")

    burst_codes = []
    for _ in range(7):
        try:
            rp = requests.post(
                f"{APP_BASE}/api/telemetry",
                json=payload,
                headers={
                    "X-App-Session-ID": "sess_burst_flood_test",
                    "X-Account-Id": "acct_burst_flood_test",
                    "X-Session-Timestamp": "1700000000",
                    "X-Session-Signature": "invalid_signature",
                },
                timeout=5,
            )
            burst_codes.append(rp.status_code)
        except requests.RequestException:
            burst_codes.append("FAIL")
    
    print(f"  [*] Perimeter Rate Limiter Burst Test (7 Requests): {burst_codes}")


if __name__ == "__main__":
    tok = phase_1_inspect_local_target()
    phase_2_verify_write_only_and_siem(tok)
    phase_3_flag_and_sink_correlation()
    phase_4_verify_lab_controls(tok)
