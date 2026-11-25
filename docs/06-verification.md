# 6. Verifying that detections fire

A detection that has never fired in a test is a guess. Most SOCs find out a rule is broken during an incident, when a field was renamed six months ago or the log shipper dropped a source. Verification closes that gap.

The method here is log replay, not attack simulation. You feed known synthetic events into a test index and check that the rule fires. No traffic is sent to any application, and nobody needs approval to run a pentest tool.

## Three layers of verification

| Layer | What it proves | Where | How often |
| --- | --- | --- | --- |
| 1. Rule logic | The rule fires on the right pattern and stays quiet on the others | This repo, in CI | Every change to a rule |
| 2. SIEM pipeline | The converted query, field mappings, and alert routing work in your SIEM | Test index in the SIEM | Every rule deploy, and monthly |
| 3. End to end | The application emits the event with the right fields, and it reaches the SIEM | UAT application plus SIEM | Every release that touches auth, authz, or payments |

### Layer 1: rule logic in CI

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_events.py     # rebuild examples/events/
python scripts/validate_events.py     # every event matches the schema
sigma check rules/sigma/              # rules are valid Sigma
python scripts/test_rules.py          # each scenario fires exactly the expected rules
```

`test_rules.py` holds a table of scenario to expected detections. It fails when a rule stops firing on its scenario, and when a rule starts firing on a scenario it should ignore. The second case catches overly broad rules before they flood the SOC.

### Layer 2: SIEM pipeline

1. Convert the rules for your backend with sigma-cli, for example `sigma convert -t splunk -p <your pipeline> rules/sigma/`. Write a processing pipeline that maps the field names in [the schema](../schema/security-event.schema.json) to your index.
2. Create a dedicated test index or tenant. Never replay into production indexes. Analysts will chase the events, and your metrics will be wrong.
3. Shift the example timestamps to now before ingest. The generator uses a fixed date so CI is deterministic.
4. Ingest one scenario file. Wait for the rule schedule. Confirm the alert, its severity, the fields in the alert body, and where it was routed.
5. Record the result in [templates/detection-test-record.md](../templates/detection-test-record.md).

### Layer 3: end to end

Synthetic events do not prove the application emits them. For that, trigger the behavior in UAT with test accounts and normal client calls:

| Detection | Safe UAT action |
| --- | --- |
| DET-AUTH-04 | Log in to a test account with a wrong password 10 times from 3 test hosts |
| DET-AUTH-06 | Deny three push prompts on a test device, then approve one |
| DET-AUTH-09 | Call the refresh endpoint twice with the same refresh token |
| DET-SESS-02 | Log out, then send the old session cookie from another test host |
| DET-AUTHZ-02 | With test user A, request statements for test user B's account |
| DET-AUTHZ-05 | Grant a privileged role to a test user through the normal admin flow |
| DET-BIZ-01 | Add a beneficiary and transfer above the floor using test funds |
| DET-BIZ-05 | Send two transfer requests with the same idempotency key and different amounts |
| DET-PLAT-01 | Flip a test security flag in UAT config |
| DET-PLAT-02 | Stop the UAT log shipper for 20 minutes |

Use only accounts and systems you own and have approval to test. Agree the test window with the SOC so nobody opens an incident.

## Keep verification running

- Schedule a monthly replay of every scenario into the test index. Alert if a rule that passed last month does not fire.
- Re-run layer 3 after any change to the identity provider, API gateway, logging library, or log shipper.
- When an incident shows a gap, add a scenario file that reproduces the event pattern with fake data, add the rule, and add the expectation in `test_rules.py`. The gap then stays closed.
