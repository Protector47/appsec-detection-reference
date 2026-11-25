# 2. Authentication and session detections

Each detection has the same layout:

- **Signal**: which events from the [logging baseline](01-logging-baseline.md) it needs
- **Logic**: what to count or correlate
- **Starting threshold**: a number to begin with. Tune it against two to four weeks of your own data before you page anyone
- **Known false positives**: what will fire that is not an attack
- **Response**: what the analyst or the app should do
- **Verify**: how to prove the rule fires, covered in detail in [06-verification.md](06-verification.md)

Thresholds below assume a retail web or mobile channel with a few hundred thousand active users. Scale them to your traffic.

## DET-AUTH-01 Credential stuffing from one source

- **Signal**: `authn_login_fail`, `authn_login_success`
- **Logic**: count distinct `user_id` (or submitted username hash) with `authn_login_fail` per `src_ip` in 10 minutes. Raise severity if any `authn_login_success` from the same IP lands in the same window.
- **Starting threshold**: 20 distinct users per IP in 10 minutes
- **Known false positives**: corporate NAT, mobile carrier CGNAT, your own branch network, synthetic monitoring
- **Response**: challenge or block the IP at the edge for a fixed period. Force a step up for every account that succeeded from that IP in the window. Check those accounts for contact or beneficiary changes after login.
- **Verify**: replay `credential-stuffing.jsonl` from the [example events](../examples/events/)
- **Sigma**: [rules/sigma/det-auth-01-credential-stuffing.yml](../rules/sigma/det-auth-01-credential-stuffing.yml)

## DET-AUTH-02 Distributed credential stuffing

Modern stuffing runs rotate through residential proxies. Per IP counts stay at one or two.

- **Signal**: `authn_login_fail`
- **Logic**: compare the global login failure ratio over 15 minutes with the same window over the last 7 days. Alert when the ratio is more than 3 standard deviations above baseline. Break down by `asn` and `user_agent` to find the cluster.
- **Starting threshold**: failure ratio over 3 sigma for two consecutive windows
- **Known false positives**: an outage in the identity provider, a bad mobile release that sends wrong credentials, a forced password reset campaign
- **Response**: turn on bot protection or a challenge for the login route. Check whether the failures share a user agent, TLS fingerprint, or header order.
- **Verify**: not practical with static samples. Use a synthetic baseline in the test index and inject a spike.

## DET-AUTH-03 Password spray

- **Signal**: `authn_login_fail` with `reason=bad_password`
- **Logic**: many distinct users, very few attempts per user (one to three), from one IP or one ASN, in 1 hour. Usernames often follow a pattern (sequential, alphabetical, from a leaked list).
- **Starting threshold**: 30 distinct users from one ASN with at most 3 failures each in 1 hour
- **Known false positives**: shared kiosks, call center networks
- **Response**: block the source. Review successful logins from the same source for the same period.
- **Verify**: replay `password-spray.jsonl`
- **Sigma**: [rules/sigma/det-auth-03-password-spray.yml](../rules/sigma/det-auth-03-password-spray.yml)

## DET-AUTH-04 Brute force on one account

- **Signal**: `authn_login_fail`, `authn_login_lock`
- **Logic**: failures for one `user_id` from more than 3 distinct IPs in 30 minutes. A single IP is usually the user. Many IPs is someone else.
- **Starting threshold**: 10 failures across 3 or more IPs in 30 minutes
- **Known false positives**: user on mobile data roaming between towers, a stale password saved in an old device
- **Response**: lock or step up. Notify the customer on a channel the attacker does not control.
- **Verify**: replay `brute-force-single-account.jsonl`

## DET-AUTH-05 Success after a failure burst

- **Signal**: `authn_login_fail`, `authn_login_success`
- **Logic**: for one `user_id`, 5 or more failures followed by a success within 15 minutes, where the success came from an IP or device not seen for this user in 30 days.
- **Known false positives**: user who forgot the password and then remembered it on a new phone
- **Response**: high priority if followed by any sensitive action (see DET-BIZ rules). Force step up on the next sensitive action.
- **Verify**: replay `credential-stuffing.jsonl`, which includes one success

## DET-AUTH-06 MFA push fatigue

- **Signal**: `authn_mfa_challenge`, `authn_mfa_fail` with `reason=denied`, `authn_mfa_success`
- **Logic**: 3 or more denied or timed out push prompts for one user in 10 minutes, followed by an approval
- **Starting threshold**: 3 denials then 1 approval in 10 minutes
- **Known false positives**: very few. Users do not usually deny their own login three times.
- **Response**: treat as account takeover until proved otherwise. Kill sessions, require a reset with identity verification. Fix the root cause by moving to number matching or a phishing resistant factor.
- **Verify**: replay `mfa-fatigue.jsonl`
- **Sigma**: [rules/sigma/det-auth-06-mfa-fatigue.yml](../rules/sigma/det-auth-06-mfa-fatigue.yml)

## DET-AUTH-07 MFA method changed then sensitive action

- **Signal**: `authn_mfa_change` or `device_bound`, followed by `beneficiary_added`, `limit_changed`, or `transfer_initiated`
- **Logic**: same `user_id`, change then sensitive action within 24 hours
- **Known false positives**: customer who got a new phone and pays rent the same day. Common, which is why this rule should raise a step up, not a block.
- **Response**: cooling off period on new beneficiaries after a device or factor change. Many banks use 12 to 24 hours.
- **Verify**: replay `device-change-then-transfer.jsonl`

## DET-AUTH-08 Password reset flood

- **Signal**: `authn_password_reset_request`
- **Logic**: count per `src_ip` and globally. Also count resets for unknown accounts (empty `user_id`), which shows enumeration attempts.
- **Starting threshold**: 10 requests per IP in 10 minutes, or global volume over 3 sigma
- **Known false positives**: a marketing email that links to reset, a forced reset after an incident
- **Response**: rate limit the route. Check SMS and email spend, since reset floods are also used to burn OTP budget (SMS pumping).
- **Verify**: replay `reset-flood.jsonl`

## DET-AUTH-09 Refresh token reuse

- **Signal**: `authn_token_reuse`
- **Logic**: any single event. With refresh token rotation, a second use of a rotated token means two parties hold the token.
- **Starting threshold**: 1
- **Known false positives**: client bugs with retries on flaky networks. Measure the rate after rollout and fix clients.
- **Response**: revoke the whole token family and the session. Log out everywhere.
- **Verify**: in staging, call the refresh endpoint twice with the same token and confirm the event and the revocation
- **Sigma**: [rules/sigma/det-auth-09-refresh-token-reuse.yml](../rules/sigma/det-auth-09-refresh-token-reuse.yml)

## DET-SESS-01 Session context change

- **Signal**: `session_context_change`, or derive it in the SIEM from `session_hash` seen with two different `asn` values
- **Logic**: same `session_hash`, different ASN or country within the session lifetime
- **Known false positives**: mobile users switching between Wi-Fi and carrier data. Compare ASN and country, not IP.
- **Response**: step up on the next sensitive action. Kill the session if the device id also changed.
- **Verify**: replay `session-hijack.jsonl`
- **Sigma**: [rules/sigma/det-sess-01-session-context-change.yml](../rules/sigma/det-sess-01-session-context-change.yml)

## DET-SESS-02 Use after logout or expiry

- **Signal**: `session_use_after_expire`
- **Logic**: count per `session_hash`. Repeated use of a revoked session from a different IP than the one that logged out is a stolen cookie.
- **Starting threshold**: 3 requests with a revoked session from a new IP in 5 minutes
- **Known false positives**: browser tabs left open, background polling in single page apps
- **Response**: confirm server side revocation works. Investigate the source.
- **Verify**: log out in staging, replay the old cookie from another host, confirm the event
