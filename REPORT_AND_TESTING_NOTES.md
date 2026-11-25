# AppSec Telemetry Assessment Testing Notes

## 1. Dynamic Verification Boundaries
Dynamic analysis was executed using internal loopback bindings across two microservice layers:
* **Port 9000**: Core application proxy router and user interaction surface.
* **Port 5000**: Telemetry capture target simulating vendor infrastructure analytics storage sinks.

## 2. Scope Constraints
Dynamic execution maps the perimeter boundaries under direct network scrutiny. Cross-tenant credential checks and rate limits require setting variables (`REQUIRE_SIGNED_SESSION = True`, `ENABLE_EDGE_RATE_LIMIT = True`) inside the host gateway file layer (`lab/app_server.py`).

## 3. Static Code Audit Execution
To evaluate front-end distributions and intercept files for signature keywords or credentials before production release phases, execute the offline parser module:
```bash
python lab/offline_cti_auditor.py --project "Enterprise Alpha Stage" --har session.har --bundle-dir dist/ --out cti_audit_report.md
```
