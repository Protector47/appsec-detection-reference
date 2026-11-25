# 7. Tuning, ownership, and response

## Before a rule pages anyone

1. Run it in report only mode for two to four weeks.
2. Count hits per day and sample 20. Label each as true positive, benign true positive (real behavior, not malicious), or false positive.
3. Adjust the threshold or add exclusions until a human would act on most hits.
4. Write the response steps in the rule's spec ([templates/detection-spec.md](../templates/detection-spec.md)). A rule without a response is noise.
5. Only then route it to a queue that someone watches.

## Exclusions done right

- Exclude by stable attributes: network ranges you own, service accounts with a documented purpose, role names. Not by user agent, which an attacker controls.
- Every exclusion gets an owner and an expiry date. Review them each quarter.
- Keep excluded hits in the index. You may need them during an investigation.

## Severity guide

| Level | Meaning | Expected handling |
| --- | --- | --- |
| informational | Base event used by correlations | Not alerted |
| low | Worth a weekly look | Hunting queue |
| medium | Needs review the same day | SOC queue |
| high | Likely malicious, act within an hour | SOC queue, page in business hours |
| critical | Active compromise or money at risk | Page 24x7, call the service owner |

## Who owns what

| Task | Owner |
| --- | --- |
| Emitting events with the right fields | Service team |
| Schema and event vocabulary | AppSec |
| Rule logic and thresholds | Detection engineering with AppSec |
| SIEM pipeline and field mapping | SIEM engineering |
| Response for account takeover and fraud rules | Fraud operations with SOC |
| Response for authz, input, and platform rules | SOC with the service team |

## Automated responses

Some detections are safe to answer in the application without waiting for a human:

| Detection | Safe automatic response |
| --- | --- |
| DET-AUTH-01, DET-AUTH-03 | Challenge or slow down the source at the edge for a fixed time |
| DET-AUTH-06 | Block further push prompts for the user for 1 hour, require a stronger factor |
| DET-AUTH-09 | Revoke the token family and the session |
| DET-BIZ-01, DET-BIZ-02 | Hold the transfer and trigger a callback |
| DET-BIZ-05 | Reject the second request (the API should already do this) |

Keep automatic responses reversible and time bound. Log every automatic action as its own event so you can measure how many customers were affected.

## Metrics worth tracking

- Rules verified in the last 30 days, as a share of all rules
- Median time from event to alert, per source
- True positive rate per rule over the last quarter
- Rules with no hits in 90 days (either the threat is absent or the rule is broken, verify which)
- Services in scope that emit the full minimum event set
