# 5. Input, data access, and platform detections

## DET-INPUT-01 Validation failure spike from one source

- **Signal**: `input_validation_fail`
- **Logic**: count per `src_ip` or `user_id` across all routes in 10 minutes. Scanners and manual testers trip validation on many fields in a short time.
- **Starting threshold**: 25 in 10 minutes from one source, across 5 or more routes
- **Known false positives**: broken client release, form autofill putting data in the wrong field
- **Response**: check whether the source is an authorized test (your own pentest or DAST). If not, block and review.
- **Verify**: replay `scanner-noise.jsonl`
- **Sigma**: [rules/sigma/det-input-01-validation-fail-spike.yml](../rules/sigma/det-input-01-validation-fail-spike.yml)

## DET-INPUT-02 Parser and template errors

- **Signal**: `malicious_input_suspect`. Emit it from global exception handlers when you catch exception types that normal input does not produce: XML external entity errors, template syntax errors from user supplied strings, deserialization type errors, SQL syntax errors from the driver, expression language errors.
- **Logic**: any event in production. These exception types should be close to zero.
- **Starting threshold**: 1 per source per hour
- **Known false positives**: a real bug in a query or template. That is also worth knowing.
- **Response**: read the stack trace (in the app log, not the security event). If a SQL syntax error was triggered by user input, treat it as a probable injection bug and get the code fixed.
- **Verify**: unit test the exception handler mapping, then replay `scanner-noise.jsonl`

## DET-INPUT-03 WAF block followed by success on the same route

- **Signal**: WAF logs joined with app access logs on `src_ip` and route
- **Logic**: source gets blocked by the WAF, then gets 2xx responses on the same route with a different payload in the next 30 minutes. This often means they found a bypass.
- **Starting threshold**: 3 blocks then 1 success with a payload length change over 50 percent
- **Known false positives**: false positive WAF blocks on normal users who retry with different input
- **Response**: compare the blocked and successful requests. If the successful one carries the same intent in a different encoding, tune the WAF and fix the code.
- **Verify**: needs WAF and app logs in the same test index. Use synthetic records.

## DET-DATA-01 Large export by a customer or integration

Covered as DET-API-03. Keep the export row count in `data_export` events so this works without parsing access logs.

## DET-DATA-02 Staff access to customer data without a reason

- **Signal**: `sensitive_read` from back office, CRM, or support tools, with `ticket_id`
- **Logic**: reads without a ticket id, reads of more than N distinct customers per shift, reads of VIP, staff, or politically exposed customer records, or reads outside the staff member's branch or region
- **Starting threshold**: 50 distinct customers per shift, or any read of a flagged record without a ticket
- **Known false positives**: collections and outbound call teams. Give them a separate baseline.
- **Response**: line manager review. Insider cases should go through HR and legal, not straight to the user.
- **Verify**: replay `insider-lookups.jsonl`
- **Sigma**: [rules/sigma/det-data-02-staff-read-without-ticket.yml](../rules/sigma/det-data-02-staff-read-without-ticket.yml)

## DET-PLAT-01 Production security config change

- **Signal**: `config_change`
- **Logic**: changes to security relevant settings (MFA enforcement, password policy, CORS origins, rate limits, logging level, feature flags that disable a control) outside an approved change window, or without a change id
- **Starting threshold**: 1
- **Response**: confirm with the change owner. Roll back if unapproved.
- **Verify**: flip a test flag in UAT, confirm event and alert
- **Sigma**: [rules/sigma/det-plat-01-security-config-change.yml](../rules/sigma/det-plat-01-security-config-change.yml)

## DET-PLAT-02 Security log silence

- **Signal**: absence of events, and `log_pipeline_error`
- **Logic**: per `app`, event volume over 15 minutes drops below 10 percent of the same window last week. Or any `log_pipeline_error`.
- **Starting threshold**: as above
- **Known false positives**: planned downtime, low traffic at night for small apps. Use the same hour last week as the baseline, not the last hour.
- **Response**: treat as a detection outage. Every other rule on this page is blind until it is fixed.
- **Verify**: stop the log shipper in UAT and confirm the alert

## DET-PLAT-03 Unexpected restarts

- **Signal**: `sys_startup`
- **Logic**: more restarts than deployments in a window. Crash loops can come from resource exhaustion attacks or from malicious input that hits an unhandled exception.
- **Starting threshold**: 3 restarts of one service in 15 minutes with no deployment event
- **Response**: check the crash cause before scaling up
- **Verify**: kill a pod in UAT three times and confirm
