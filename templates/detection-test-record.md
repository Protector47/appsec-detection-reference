# Detection test record

| Field | Value |
| --- | --- |
| Date | YYYY-MM-DD |
| Tester | |
| Environment | test index / UAT |
| SIEM rule version | |

| Detection | Scenario or UAT action | Expected | Fired | Severity correct | Routed correctly | Time to alert | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| DET-AUTH-01 | credential-stuffing.jsonl | Alert | | | | | |
| DET-AUTH-03 | password-spray.jsonl | Alert | | | | | |
| DET-AUTH-06 | mfa-fatigue.jsonl | Alert | | | | | |
| DET-AUTH-09 | refresh-token-reuse.jsonl | Alert | | | | | |
| DET-SESS-01 | session-hijack.jsonl | Alert | | | | | |
| DET-AUTHZ-01 | object-level-probe.jsonl | Alert | | | | | |
| DET-AUTHZ-02 | object-level-probe.jsonl | Alert | | | | | |
| DET-AUTHZ-04 | admin-route-probe.jsonl | Alert | | | | | |
| DET-AUTHZ-05 | privileged-grant.jsonl | Alert | | | | | |
| DET-BIZ-01 | account-takeover-chain.jsonl | Alert | | | | | |
| DET-BIZ-05 | idempotency-conflict.jsonl | Alert | | | | | |
| DET-INPUT-01 | scanner-noise.jsonl | Alert | | | | | |
| DET-INPUT-02 | scanner-noise.jsonl | Alert | | | | | |
| DET-DATA-02 | insider-lookups.jsonl | Alert | | | | | |
| DET-PLAT-01 | config-change.jsonl | Alert | | | | | |

## Failures and follow up

| Detection | What went wrong | Ticket | Owner |
| --- | --- | --- | --- |
| | | | |
