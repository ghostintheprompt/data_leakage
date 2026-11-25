# Data Leak Lab — Enterprise AppSec & CTI Assessment Suite

Self-contained AppSec and Cyber Threat Intelligence (CTI) verification suite demonstrating telemetry-induced OpSec metadata exposure, write-only client token triage, tripwire canary revocation, and defense-in-depth proxy remediation.

## Quick Start

Run from the repository root:

```bash
pip install -r lab/requirements.txt
python lab/telemetry_sink.py   # Terminal 1 — Intake sink & /dashboard (Port 5000)
python lab/app_server.py       # Terminal 2 — Target gateway & UI (Port 9000)
python lab/red_team_recon.py   # Terminal 3 — Automated verification suite
```

Open **`http://127.0.0.1:9000`** in your browser for the interactive walkthrough and **`http://127.0.0.1:5000/dashboard`** to inspect captured telemetry indicators.

## Repository Guide

- **Full Walkthrough & Stage Controls:** [`lab/README.md`](lab/README.md)
- **Quick Command Reference:** [`Engagement_Quick_Reference.md`](Engagement_Quick_Reference.md)
- **Verification & Scope Notes:** [`REPORT_AND_TESTING_NOTES.md`](REPORT_AND_TESTING_NOTES.md)
- **Offline HAR/Bundle Auditor:** [`lab/offline_cti_auditor.py`](lab/offline_cti_auditor.py)
- **SIEM / Edge Detection Rules:** [`lab/soc_detections.yml`](lab/soc_detections.yml)
