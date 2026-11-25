# Engagement Quick Reference Sheet: Operational Telemetry Assessment

## 1. Environment Map
* **Target Domain Gateway**: `http://localhost:9000`
* **Telemetry Intake Receiver Base**: `http://localhost:5000`
* **Exposed Analytics Client Token**: `pub_placeholder_token_abc123xyz789`
* **Assessment Scope Profile**: Operational Security Info-Leak Verification

## 2. Server Repository File Locations
* **Backend CTI Engine / Intake Handler**: `lab/telemetry_sink.py`
* **Main Host Application Routing**: `lab/app_server.py`
* **Automation Assessment Payloads**: `lab/red_team_recon.py`
* **Frontend Component Context**: `src/main.tsx` and `src/App.tsx`
* **Offline Asset Parser Suite**: `lab/offline_cti_auditor.py`

## 3. Ingestion Proof Checklist
Execute a live verification data dump to ensure path boundaries are active:
```bash
curl -i -X POST "http://localhost:5000/api/v2/rum?dd-api-key=pub_placeholder_token_abc123xyz789" \
     -H "Content-Type: application/json" \
     -d '{"resource": {"url": "/workflows/flow_stealth_alpha_99x/stream"}, "message": "Verification framework check"}'
```
