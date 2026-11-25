# Data Leak Lab — Enterprise AppSec & CTI Replication Suite

## Scenario
TargetCorp is running a live testing alpha phase for an unreleased, highly autonomous workflow orchestrator architecture. While core transactional ledgers and primary databases remain cryptographically secure, standard default third-party frontend observability SDKs (Datadog RUM & PostHog), client JS bundles, SSE streams, and corporate HTTP routing logs are leaking critical operational blueprints, microservice graph topologies, system execution fingerprints, and configuration contexts over the public internet.

---

## 1. Quick Start (Assessment Environment Execution)
This repository functions as a self-contained, non-destructive replication environment to demonstrate, validate, and remediate information disclosure risks without impacting downstream vendor production environments.

1. **Install dependencies (from repository root):**
   ```bash
   pip install -r lab/requirements.txt
   ```
2. **Start the CTI Telemetry Intake Sink (Terminal 1 - Port 5000):**
   ```bash
   python lab/telemetry_sink.py
   ```
3. **Start the Target Application Server & Gateway Proxy (Terminal 2 - Port 9000):**
   ```bash
   python lab/app_server.py
   ```
4. **Generate Operational Activity:**
   Open `http://127.0.0.1:9000` in your browser (with **DevTools → Network** open) and click **Run Agent Trajectory + SSE Stream** and **Simulate Step Error Boundary**.
5. **Execute Automated Verification Engine (Terminal 3):**
   ```bash
   python lab/red_team_recon.py
   ```

*Note: Access the application interface via Port `9000` directly so Flask dynamically injects runtime configuration and negotiates short-lived HMAC session tokens without timeout errors. Because both servers run with `debug=False`, restart the corresponding terminal (`Ctrl+C`, then rerun `python ...`) whenever you change a configuration flag.*

---

## 2. Advanced Security Invariants Verified

This suite implements and tests enterprise-grade defensive abstractions designed to lock down agentic workflows:

*   **Task-Scoped MCP Tool Menus:** Limits client visibility strictly to narrow-horizon `/workflows/` scopes rather than allowing arbitrary system tool execution hooks.
*   **Dynamic HMAC Token Exchange:** Eliminates long-lived ambient credentials in the browser context by forcing the client to automatically negotiate a short-lived, single-use transaction signature via `/api/session-token` before dispatching error boundaries.
*   **Zero-Noise Tripwire Canaries:** Embeds non-permissioned decoy values (`decoy_credential`, `vault_root_key`) into data structures. Any unauthorized read probe from an agent context triggers an instant low-noise alert that dynamically blacklists the session ID and revokes active token privileges.

---

## 3. Operational Testing Stages

### Stage 1: Token Capability Triage & Ingestion Pipeline Log Leakage
- With **DevTools → Network** open on `http://127.0.0.1:9000`, click **Run Agent Trajectory + SSE Stream** and **Simulate Step Error Boundary**, then locate `dd-api-key=pub_placeholder_token_abc123xyz789` in the outbound request URLs.
- Run `python lab/red_team_recon.py` (or query `/api/v1/monitor`, `/api/v1/logs-queries`, and `/api/v1/org` on Port `5000`) to confirm that public client tokens return `403 Forbidden` and are strictly **Write-Only** (Low Infrastructure Breach Risk), while still creating **URI Log Leakage** and **Denial-of-Wallet** exposure.
- To evaluate log masking and volume caps, set `SIEM_MASK_DD_KEY = True` and `ENFORCE_VOLUME_CAP = True` in `lab/telemetry_sink.py` and **restart Terminal 1**.

### Stage 2: Workflow Fingerprinting & Graph Topology Disclosures
- After clicking **Run Agent Trajectory + SSE Stream** and **Simulate Step Error Boundary** on `http://127.0.0.1:9000`, inspect the real-time parsing analysis at `http://127.0.0.1:5000/dashboard`.
- Observe how unhardened telemetry payloads broadcast execution latencies (`>= 1500ms`), token footprints (`>= 3000` tokens), SSE microservice node sequences, host file paths (`/srv/app/`), and internal configuration contexts.

### Stage 3: Zero-Noise Tripwire Canary Activation
- Click **Trip Wire Canary** on `http://127.0.0.1:9000` to simulate an agent probing a decoy credential token out of scope.
- Observe the immediate `403 Forbidden` response with `Security Boundary Fault: Identity Revoked`.
- Rerun `python lab/red_team_recon.py` to confirm that `sess_alpha_0001` has been blacklisted (`403`) on subsequent `/api/telemetry` probes.

### Stage 4: Full Production Defense-in-Depth Activation
In `lab/app_server.py`, set all production gateway guards to `True`:
```python
USE_STEALTH_PROXY = True               # Routes all analytical data securely behind the firewall
REQUIRE_SIGNED_SESSION = True           # Enforces ephemeral HMAC token validation
ENFORCE_ACCOUNT_SESSION_BINDING = True # Prevents cross-tenant parameter spoofing
ENABLE_EDGE_RATE_LIMIT = True          # Automatically blocks rapid-fire command-line scripts
HEADER_ONLY_TOKEN_FORWARDING = True    # Strips active tokens out of public URL request strings
MASK_TRAJECTORY_PATHS = True           # Obfuscates raw database paths with opaque strings
```
**Restart Terminal 2** (`Ctrl+C`, then `python lab/app_server.py` — this also clears the Stage 3 in-memory canary blacklist), re-click the buttons at `http://127.0.0.1:9000`, and rerun `python lab/red_team_recon.py` to confirm full remediation across the interface.

---

## 4. Offline Auditing & SOC Deliverables
- **Offline HAR/Bundle Auditor:** `python lab/offline_cti_auditor.py --project "Enterprise Alpha Stage" --har session.har --bundle-dir dist/ --out cti_audit_report.md`
- **SIEM/Proxy Alerting Rules:** `lab/soc_detections.yml`
- **Methodology & Testing Scope Notes:** `REPORT_AND_TESTING_NOTES.md` and `Engagement_Quick_Reference.md`
