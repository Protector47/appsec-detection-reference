# Sigma rules

Rules for the detections in [docs/](../../docs/). They use the [Sigma](https://github.com/SigmaHQ/sigma-specification) format, including correlation rules for thresholds and sequences.

## Log source

All rules use a custom log source:

```yaml
logsource:
    product: appsec
    service: security_events
```

Field names match [schema/security-event.schema.json](../../schema/security-event.schema.json). Write a sigma-cli processing pipeline that maps this log source and these fields to your index.

## Rule types in this folder

- Rules with `level: informational` and a `name` are base rules. Correlations reference them by name. Do not alert on them directly.
- Rules with a `DET-...` id in the title are the alerting detections.
- Thresholds are starting points from retail banking traffic. Tune them on your own data first ([docs/07-tuning-and-response.md](../../docs/07-tuning-and-response.md)).
- Amounts are in minor units. `25000000` is PKR 250,000. Change the floor to match your currency and risk appetite.

## Check and convert

```bash
sigma check rules/sigma/
sigma plugin install splunk
sigma convert -t splunk --without-pipeline rules/sigma/det-auth-01-credential-stuffing.yml
```

`--without-pipeline` is fine for a quick look. Use a real pipeline for production.

## Index

| File | Detections |
| --- | --- |
| [det-auth-01-credential-stuffing.yml](det-auth-01-credential-stuffing.yml) | DET-AUTH-01 |
| [det-auth-03-password-spray.yml](det-auth-03-password-spray.yml) | DET-AUTH-03 |
| [det-auth-06-mfa-fatigue.yml](det-auth-06-mfa-fatigue.yml) | DET-AUTH-06 |
| [det-auth-09-refresh-token-reuse.yml](det-auth-09-refresh-token-reuse.yml) | DET-AUTH-09 |
| [det-sess-01-session-context-change.yml](det-sess-01-session-context-change.yml) | DET-SESS-01 |
| [det-authz-01-authz-fail-spike.yml](det-authz-01-authz-fail-spike.yml) | DET-AUTHZ-01, DET-AUTHZ-02 |
| [det-authz-04-admin-route-non-admin.yml](det-authz-04-admin-route-non-admin.yml) | DET-AUTHZ-04 |
| [det-authz-05-privileged-role-granted.yml](det-authz-05-privileged-role-granted.yml) | DET-AUTHZ-05 |
| [det-biz-01-new-beneficiary-transfer.yml](det-biz-01-new-beneficiary-transfer.yml) | DET-BIZ-01 |
| [det-biz-05-idempotency-conflict.yml](det-biz-05-idempotency-conflict.yml) | DET-BIZ-05 |
| [det-input-01-validation-fail-spike.yml](det-input-01-validation-fail-spike.yml) | DET-INPUT-01, DET-INPUT-02 |
| [det-data-02-staff-read-without-ticket.yml](det-data-02-staff-read-without-ticket.yml) | DET-DATA-02 |
| [det-plat-01-security-config-change.yml](det-plat-01-security-config-change.yml) | DET-PLAT-01 |

Detections in the docs without a rule here (for example DET-AUTH-02 or DET-PLAT-02) need baselines or joins that Sigma does not express well. Build those directly in your SIEM.
