#!/usr/bin/env python3
"""Generate synthetic security events for detection testing.

Writes one JSONL file per scenario into examples/events/. Output is
deterministic (fixed seed, fixed start time) so CI can check that the
committed files match the generator.

All IPs come from documentation ranges (RFC 5737, RFC 3849) and all ASNs
from the documentation range (RFC 5398). Every user, device, and resource
is fake. Replay these into a test index, never into production.
"""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "examples" / "events"
START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
APP = "retail-banking-api"
UA_WEB = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"
UA_APP = "BankApp/7.4.1 (Android 14)"
UA_SCRIPT = "python-requests/2.32.3"


class Scenario:
    def __init__(self, name: str, seed: int) -> None:
        self.name = name
        self.rng = random.Random(seed)
        self.t = START
        self.events: list[dict] = []

    def tick(self, seconds: float) -> None:
        self.t += timedelta(seconds=seconds)

    def rid(self) -> str:
        return "%016x" % self.rng.getrandbits(64)

    def emit(self, event: str, outcome: str, src_ip: str, level: str = "INFO", **fields) -> None:
        rec = {
            "ts": self.t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (self.t.microsecond // 1000),
            "event": event,
            "level": level,
            "app": APP,
            "env": "test",
            "request_id": self.rid(),
            "src_ip": src_ip,
            "outcome": outcome,
        }
        rec.update({k: v for k, v in fields.items() if v is not None})
        self.events.append(rec)

    def write(self) -> None:
        OUT.mkdir(parents=True, exist_ok=True)
        path = OUT / f"{self.name}.jsonl"
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for rec in self.events:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def user(n: int) -> str:
    return f"u-{n:05d}"


def credential_stuffing() -> Scenario:
    s = Scenario("credential-stuffing", 1)
    ip = "203.0.113.7"
    for i in range(40):
        s.tick(s.rng.uniform(3, 9))
        s.emit("authn_login_fail", "failure", ip, user_id=user(10000 + i * 37), reason="bad_password",
               user_agent=UA_SCRIPT, asn=64500, geo_country="NL", channel="web", route="/api/v2/auth/login")
        if i in (11, 29):
            s.tick(1)
            s.emit("authn_login_success", "success", ip, user_id=user(10000 + i * 37), user_agent=UA_SCRIPT,
                   asn=64500, geo_country="NL", channel="web", route="/api/v2/auth/login",
                   session_hash=h(f"stuff-{i}"))
    return s


def password_spray() -> Scenario:
    s = Scenario("password-spray", 2)
    for i in range(45):
        s.tick(s.rng.uniform(40, 80))
        ip = f"198.51.100.{10 + i % 6}"
        s.emit("authn_login_fail", "failure", ip, user_id=user(20000 + i), reason="bad_password",
               user_agent=UA_WEB, asn=64501, geo_country="US", channel="web", route="/api/v2/auth/login")
    return s


def brute_force_single_account() -> Scenario:
    s = Scenario("brute-force-single-account", 3)
    for i in range(14):
        s.tick(s.rng.uniform(60, 120))
        s.emit("authn_login_fail", "failure", f"192.0.2.{20 + i % 5}", user_id=user(30001),
               reason="bad_password", user_agent=UA_WEB, asn=64502 + i % 3, geo_country="DE", channel="web")
    s.tick(2)
    s.emit("authn_login_lock", "failure", "192.0.2.24", level="WARN", user_id=user(30001), reason="threshold")
    return s


def mfa_fatigue() -> Scenario:
    s = Scenario("mfa-fatigue", 4)
    ip = "203.0.113.45"
    u = user(40001)
    s.emit("authn_login_success", "success", ip, user_id=u, asn=64505, geo_country="RO", user_agent=UA_WEB)
    for i in range(4):
        s.tick(60)
        s.emit("authn_mfa_challenge", "success", ip, user_id=u, mfa_type="push")
        s.tick(25)
        s.emit("authn_mfa_fail", "failure", ip, user_id=u, mfa_type="push", reason="denied")
    s.tick(60)
    s.emit("authn_mfa_challenge", "success", ip, user_id=u, mfa_type="push")
    s.tick(12)
    s.emit("authn_mfa_success", "success", ip, user_id=u, mfa_type="push")
    return s


def device_change_then_transfer() -> Scenario:
    s = Scenario("device-change-then-transfer", 5)
    ip = "198.51.100.77"
    u = user(50001)
    s.emit("authn_login_success", "success", ip, user_id=u, device_id="dev-new-9f2c", user_agent=UA_APP, channel="mobile")
    s.tick(90)
    s.emit("device_bound", "success", ip, level="WARN", user_id=u, device_id="dev-new-9f2c", channel="mobile")
    s.tick(600)
    s.emit("beneficiary_added", "success", ip, user_id=u, beneficiary_id="ben-7781", channel="mobile")
    s.tick(120)
    s.emit("transfer_initiated", "success", ip, user_id=u, beneficiary_id="ben-7781", amount=45000000,
           currency="PKR", destination_type="new_beneficiary", channel="mobile")
    return s


def reset_flood() -> Scenario:
    s = Scenario("reset-flood", 6)
    ip = "203.0.113.90"
    for i in range(30):
        s.tick(s.rng.uniform(5, 15))
        known = i % 4 == 0
        s.emit("authn_password_reset_request", "success" if known else "failure", ip,
               user_id=user(60000 + i) if known else None, reason=None if known else "unknown_account",
               user_agent=UA_SCRIPT, route="/api/v2/auth/reset")
    return s


def session_hijack() -> Scenario:
    s = Scenario("session-hijack", 7)
    u = user(70001)
    sh = h("session-70001")
    s.emit("session_created", "success", "192.0.2.10", user_id=u, session_hash=sh, asn=64496, geo_country="PK", user_agent=UA_WEB)
    s.tick(300)
    s.emit("session_renewed", "success", "192.0.2.10", user_id=u, session_hash=sh, asn=64496, geo_country="PK", user_agent=UA_WEB)
    s.tick(240)
    s.emit("session_context_change", "success", "203.0.113.200", level="WARN", user_id=u, session_hash=sh,
           asn=64510, geo_country="BR", user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0")
    return s


def object_level_probe() -> Scenario:
    s = Scenario("object-level-probe", 8)
    ip = "198.51.100.33"
    u = user(80001)
    for i in range(20):
        s.tick(s.rng.uniform(4, 12))
        s.emit("authz_fail", "failure", ip, level="WARN", user_id=u, route="/api/v2/accounts/{id}/statements",
               resource_type="account", resource_id=f"acc-{100200 + i}", resource_owner=user(81000 + i), reason="policy_deny")
    return s


def admin_route_probe() -> Scenario:
    s = Scenario("admin-route-probe", 9)
    ip = "203.0.113.61"
    u = user(90001)
    for route in ("/admin/users", "/internal/config", "/actuator/env", "/management/health"):
        s.tick(20)
        s.emit("authz_fail", "failure", ip, level="WARN", user_id=u, role="customer", route=route, reason="role_deny")
    return s


def mass_assignment() -> Scenario:
    s = Scenario("mass-assignment", 10)
    ip = "198.51.100.140"
    u = user(10101)
    for fields in (["role"], ["isAdmin"], ["dailyLimit", "kycStatus"], ["ownerId"]):
        s.tick(45)
        s.emit("input_unexpected_field", "failure", ip, level="WARN", user_id=u, route="/api/v2/profile",
               fields=fields, reason="unexpected_field")
    return s


def bulk_export() -> Scenario:
    s = Scenario("bulk-export", 11)
    ip = "192.0.2.150"
    u = user(11001)
    for i in range(12):
        s.tick(30)
        s.emit("data_export", "success", ip, user_id=u, route="/api/v2/customers/search", row_count=500,
               channel="api", description=f"page {i + 1}")
    return s


def account_takeover_chain() -> Scenario:
    s = Scenario("account-takeover-chain", 12)
    ip = "203.0.113.130"
    u = user(12001)
    sh = h("ato-12001")
    for _ in range(6):
        s.tick(20)
        s.emit("authn_login_fail", "failure", ip, user_id=u, reason="bad_password", asn=64507, geo_country="GB")
    s.tick(30)
    s.emit("authn_login_success", "success", ip, user_id=u, session_hash=sh, device_id="dev-unknown-01", asn=64507, geo_country="GB")
    s.tick(120)
    s.emit("contact_updated", "success", ip, level="WARN", user_id=u, session_hash=sh, field="mobile_number")
    s.tick(400)
    s.emit("beneficiary_added", "success", ip, user_id=u, session_hash=sh, beneficiary_id="ben-9902")
    s.tick(300)
    s.emit("transfer_initiated", "success", ip, user_id=u, session_hash=sh, beneficiary_id="ben-9902",
           amount=95000000, currency="PKR", destination_type="new_beneficiary")
    return s


def limit_raise_drain() -> Scenario:
    s = Scenario("limit-raise-drain", 13)
    ip = "198.51.100.88"
    u = user(13001)
    s.emit("limit_changed", "success", ip, level="WARN", user_id=u, field="daily_transfer_limit", old_value=50000000, new_value=200000000)
    for amt in (99000000, 80000000):
        s.tick(900)
        s.emit("transfer_initiated", "success", ip, user_id=u, amount=amt, currency="PKR", destination_type="beneficiary")
    return s


def below_threshold_transfers() -> Scenario:
    s = Scenario("below-threshold-transfers", 14)
    ip = "192.0.2.180"
    u = user(14001)
    for _ in range(6):
        s.tick(s.rng.uniform(1800, 5400))
        s.emit("transfer_initiated", "success", ip, user_id=u, amount=s.rng.randint(9600000, 9990000),
               currency="PKR", destination_type="beneficiary", description="step up threshold is 10000000")
    return s


def tampered_amounts() -> Scenario:
    s = Scenario("tampered-amounts", 15)
    ip = "203.0.113.150"
    u = user(15001)
    for reason in ("negative_amount", "zero_amount", "precision_exceeded"):
        s.tick(40)
        s.emit("transfer_rejected", "failure", ip, level="WARN", user_id=u, field="amount", reason=reason)
    return s


def promo_abuse() -> Scenario:
    s = Scenario("promo-abuse", 16)
    ip = "198.51.100.200"
    for i in range(4):
        s.tick(3600)
        s.emit("promo_redeemed", "success", ip, user_id=user(16000 + i), device_id="dev-shared-55aa",
               promo_code_hash=h("SIGNUP500"), channel="mobile")
    return s


def scanner_noise() -> Scenario:
    s = Scenario("scanner-noise", 17)
    ip = "203.0.113.250"
    routes = ["/api/v2/search", "/api/v2/profile", "/api/v2/billers", "/api/v2/cards/{id}", "/api/v2/support/ticket", "/api/v2/feedback"]
    for i in range(30):
        s.tick(s.rng.uniform(2, 8))
        s.emit("input_validation_fail", "failure", ip, route=routes[i % len(routes)], field="q", reason="pattern_mismatch", user_agent=UA_SCRIPT)
    for r in ("sql_syntax_error", "template_syntax_error"):
        s.tick(5)
        s.emit("malicious_input_suspect", "failure", ip, level="CRITICAL", route="/api/v2/search", reason=r, user_agent=UA_SCRIPT)
    return s


def insider_lookups() -> Scenario:
    s = Scenario("insider-lookups", 18)
    ip = "192.0.2.5"
    for i in range(60):
        s.tick(s.rng.uniform(20, 60))
        s.emit("sensitive_read", "success", ip, user_id="staff-0451", role="support_agent", channel="backoffice",
               resource_type="customer_profile", resource_owner=user(18000 + i), ticket_id="TCK-88120" if i < 3 else None)
    return s


def privileged_grant() -> Scenario:
    s = Scenario("privileged-grant", 19)
    s.emit("authz_change", "success", "192.0.2.9", level="CRITICAL", user_id="staff-0099", role="iam_admin",
           resource_type="user", resource_id="staff-0099", new_value="payments_approver", channel="backoffice")
    return s


def config_change() -> Scenario:
    s = Scenario("config-change", 20)
    s.emit("config_change", "success", "192.0.2.12", level="WARN", user_id="staff-0210", setting="auth.mfa.enforced",
           old_value="true", new_value="false", channel="backoffice")
    return s


def refresh_token_reuse() -> Scenario:
    s = Scenario("refresh-token-reuse", 21)
    u = user(21001)
    s.emit("session_renewed", "success", "192.0.2.40", user_id=u, session_hash=h("rt-21001"), channel="mobile")
    s.tick(400)
    s.emit("authn_token_reuse", "failure", "203.0.113.41", level="CRITICAL", user_id=u, session_hash=h("rt-21001"), reason="rotated_token_reused")
    return s


def idempotency_conflict() -> Scenario:
    s = Scenario("idempotency-conflict", 22)
    u = user(22001)
    s.emit("transfer_initiated", "success", "198.51.100.9", user_id=u, amount=1000000, currency="PKR", destination_type="beneficiary")
    s.tick(0.2)
    s.emit("idempotency_conflict", "failure", "198.51.100.9", level="CRITICAL", user_id=u, amount=90000000, currency="PKR", reason="payload_mismatch")
    return s


SCENARIOS = [
    credential_stuffing, password_spray, brute_force_single_account, mfa_fatigue,
    device_change_then_transfer, reset_flood, session_hijack, object_level_probe,
    admin_route_probe, mass_assignment, bulk_export, account_takeover_chain,
    limit_raise_drain, below_threshold_transfers, tampered_amounts, promo_abuse,
    scanner_noise, insider_lookups, privileged_grant, config_change,
    refresh_token_reuse, idempotency_conflict,
]


def main() -> None:
    for build in SCENARIOS:
        build().write()
    print(f"Wrote {len(SCENARIOS)} scenario files to {OUT}")


if __name__ == "__main__":
    main()
