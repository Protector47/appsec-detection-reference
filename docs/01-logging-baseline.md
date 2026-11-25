# 1. Application logging baseline

Most application attacks never touch the network layer in a way your IDS can see. A credential stuffing run, a broken object level authorization probe, or a fraudulent beneficiary add all look like normal HTTPS. The only place they show up is the application's own logs. If the app does not emit the right event, no SIEM rule will save you.

This page defines the minimum security events every service should emit, and the fields each event needs. Event names follow the [OWASP Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html) where one exists. Business events (transfers, beneficiaries, limits) are our additions.

The machine readable version is [schema/security-event.schema.json](../schema/security-event.schema.json).

## Rules for the logging pipeline

1. Emit security events as structured JSON, one event per line. No free text parsing in the SIEM.
2. Use UTC timestamps in RFC 3339 with milliseconds. Clock drift between nodes breaks every correlation rule.
3. Log the outcome of the decision, not just the request. A `403` in the access log is not the same as `authz_fail` with the user, the resource, and the policy that denied it.
4. Emit from the server side only. Client side logs can be forged and are useful only as hints.
5. Ship security events to a separate index or stream with longer retention than debug logs. Check your regulator's retention rule. Banking regulators commonly expect a year or more.
6. Make the security log path fail loudly. If the logger cannot write, raise an alert. Silent log loss is a detection gap nobody notices until incident day.
7. Protect the logs. Write only from the app, read only for the SOC and named engineers. Developers should not be able to delete production security logs.

## Required fields

| Field | Type | Notes |
| --- | --- | --- |
| `ts` | string | RFC 3339 UTC, for example `2026-11-25T05:30:12.481Z` |
| `event` | string | Vocabulary name, for example `authn_login_fail` |
| `level` | string | `INFO`, `WARN`, or `CRITICAL` |
| `app` | string | Service name as known in the CMDB |
| `env` | string | `prod`, `uat`, `dev` |
| `request_id` | string | Correlation id, propagated across services |
| `src_ip` | string | Client IP after trusted proxy resolution. Never take `X-Forwarded-For` blindly |
| `outcome` | string | `success` or `failure` |

## Recommended fields

| Field | Notes |
| --- | --- |
| `user_id` | Internal stable id. Not the email, not the CNIC, not the phone number |
| `tenant_id` | For multi tenant systems. Needed for cross tenant access detections |
| `session_hash` | SHA-256 of the session id, truncated. Lets you track a session without logging the secret |
| `device_id` | App generated install id for mobile, or a fingerprint hash for web |
| `user_agent` | Truncate to 256 characters |
| `asn` / `geo_country` | Enrich at ingest, not in the app |
| `route` | The route template (`/api/v1/accounts/{id}`), not the raw path |
| `resource_type` / `resource_id` | What object was touched |
| `resource_owner` | Owner id of the object, so you can compare it with `user_id` |
| `reason` | Short machine code for why it failed: `bad_password`, `mfa_denied`, `policy_deny` |
| `amount` / `currency` | For money movement events. Integer minor units |
| `channel` | `web`, `mobile`, `api`, `branch`, `ivr` |

## Minimum event set

### Authentication

| Event | When |
| --- | --- |
| `authn_login_success` | Primary credential accepted (before or after MFA, log both stages) |
| `authn_login_fail` | Bad credential. Include `reason` |
| `authn_login_lock` | Account locked by threshold |
| `authn_mfa_challenge` | MFA prompt sent. Include `mfa_type` |
| `authn_mfa_success` / `authn_mfa_fail` | MFA outcome. `reason=denied` for push rejections |
| `authn_password_change` | Password changed by user |
| `authn_mfa_change` | MFA factor added, removed, or replaced |
| `authn_password_reset_request` | Reset requested. Log even for unknown accounts, with `user_id` empty |
| `authn_token_created` / `authn_token_revoked` | API keys, refresh tokens, personal access tokens |
| `authn_token_reuse` | A rotated refresh token was presented again |
| `authn_impossible_travel` | Only if computed in the app. Usually better done in the SIEM |

### Session

| Event | When |
| --- | --- |
| `session_created` | New session after login |
| `session_renewed` | Rotation or refresh |
| `session_expired` | Idle or absolute timeout |
| `session_use_after_expire` | Request arrived with an expired or revoked session |
| `session_context_change` | Same session seen with a new IP block, ASN, or user agent |

### Authorization

| Event | When |
| --- | --- |
| `authz_fail` | Any policy deny. Include `resource_type`, `resource_id`, `resource_owner` if known |
| `authz_change` | Role or permission granted or removed |
| `authz_admin` | Admin or privileged function used |

### Input and data

| Event | When |
| --- | --- |
| `input_validation_fail` | Server side validation rejected input. Include field name, never the value |
| `input_unexpected_field` | Request carried fields the API does not accept (mass assignment attempts) |
| `malicious_input_suspect` | Parser or template engine raised an error that should not happen with normal input |
| `data_export` | Bulk download, report export, statement generation. Include row count |
| `sensitive_read` | Staff or support read of customer PII. Include `ticket_id` if your process needs one |

### Business events (banking and payments)

| Event | When |
| --- | --- |
| `beneficiary_added` / `beneficiary_removed` | Payee list changed |
| `contact_updated` | Mobile number, email, or address changed. Include which field |
| `limit_changed` | Transaction limit changed. Include old and new value |
| `transfer_initiated` / `transfer_completed` / `transfer_rejected` | Money movement. Include amount, currency, destination type |
| `idempotency_conflict` | Same idempotency key presented with a different payload |
| `device_bound` / `device_unbound` | Mobile device registration changed |

### Platform

| Event | When |
| --- | --- |
| `config_change` | Feature flag, security setting, or integration secret changed in prod |
| `sys_startup` / `sys_shutdown` | Service lifecycle. Useful to spot unexpected restarts |
| `log_pipeline_error` | Logger could not write or ship events |

## Never log

- Passwords, OTPs, PINs, CVV, full PAN, private keys, session ids, bearer tokens, API keys
- Full request bodies on auth, payment, or KYC endpoints
- National id numbers, full account numbers (mask to last 4), biometric data
- The value that failed validation. Log the field name and the rule

Add a unit test that serializes your log event types and fails if any field name matches `password|otp|pin|token|secret|cvv|pan`. It catches most regressions for free.

## Quick self check for a service

- [ ] Every row in the minimum event set that applies to this service is emitted
- [ ] `src_ip` is the real client IP, verified behind the load balancer and CDN
- [ ] `request_id` is the same across the gateway, the service, and downstream calls
- [ ] `authz_fail` includes the resource and owner, not just the route
- [ ] Sensitive fields are absent from a sample of 1,000 production events
- [ ] Logger failure raises an alert
- [ ] Events reach the SIEM within the latency your detections assume (usually under 2 minutes)
