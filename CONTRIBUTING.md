# Contributing

Pull requests are welcome, especially from people who run detections against real application traffic.

## Good contributions

- New detections with signal, logic, threshold, false positives, response, and a way to verify
- Threshold data from production ("we started at 20, ended at 35 because of CGNAT")
- sigma-cli processing pipelines for specific SIEMs that map the schema fields
- New scenario builders in `scripts/generate_events.py` with matching expectations in `scripts/test_rules.py`
- Corrections where a rule is wrong or a field is missing from the schema

## Adding a detection

1. Describe it in the right page under `docs/` using the same layout as the existing entries.
2. If it fits Sigma, add a rule under `rules/sigma/` with the `DET-...` id in the title.
3. Add a scenario builder that produces events which should fire it, using documentation IP ranges and fake ids only.
4. Add the expectation to the `EXPECTED` table in `scripts/test_rules.py`.
5. Regenerate the events and run all checks.

## Out of scope

This repo is for defenders watching systems they own. Attack tooling, exploit code, payload lists, or instructions for testing systems you do not own will not be merged. Example events must stay synthetic. Never commit real logs, real IPs, or customer data.

## Checks

```bash
pip install -r requirements.txt
python scripts/generate_events.py && git diff --exit-code examples/events/
python scripts/validate_events.py
sigma check rules/sigma/
python scripts/test_rules.py
npx markdownlint-cli2 "**/*.md"
bash scripts/check-style.sh
```

## Style

- Short, direct sentences. Write like notes for your own team.
- No em dashes or en dashes as punctuation. Use commas, periods, or parentheses.
- Every detection says what to do when it fires.
