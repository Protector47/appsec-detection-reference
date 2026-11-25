# 4. Business logic and fraud adjacent detections

Business logic abuse uses valid features in an order or at a speed the designers did not expect. WAFs and scanners do not see it. These rules come from digital banking and payments, but the pattern (sensitive change, then value extraction) fits any app that moves money, points, or credit.

Coordinate with your fraud team before deploying these. Many banks already run a transaction monitoring engine, and you do not want two systems blocking the same customer for different reasons. The AppSec value here is the application context (device, session, login history) that fraud engines often do not get.

## DET-BIZ-01 New beneficiary then high value transfer

- **Signal**: `beneficiary_added`, `transfer_initiated`
- **Logic**: same `user_id`, transfer to the newly added beneficiary within 30 minutes, with amount above the customer's 90 day 95th percentile or above a fixed floor
- **Starting threshold**: within 30 minutes and amount above the floor your fraud team sets
- **Known false positives**: first payment to a new landlord, school, or supplier. Very common at month start.
- **Response**: hold and call back on the registered number, or apply a cooling period on new beneficiaries. Risk is much higher if DET-AUTH-05, DET-AUTH-07, or DET-SESS-01 also fired in the same session.
- **Verify**: replay `account-takeover-chain.jsonl`
- **Sigma**: [rules/sigma/det-biz-01-new-beneficiary-transfer.yml](../rules/sigma/det-biz-01-new-beneficiary-transfer.yml)

## DET-BIZ-02 Contact detail change then sensitive action

- **Signal**: `contact_updated` (mobile number or email), followed by `beneficiary_added`, `limit_changed`, `device_bound`, or `transfer_initiated`
- **Logic**: same `user_id` within 72 hours. Changing the mobile number moves OTP delivery to the attacker. This is the core of SIM swap and social engineering takeover.
- **Starting threshold**: any sensitive action within 72 hours of a mobile number change
- **Known false positives**: customers who really changed numbers. Expect a steady low volume.
- **Response**: notify the old number and email about the change. Hold high value actions until verified.
- **Verify**: replay `account-takeover-chain.jsonl`

## DET-BIZ-03 Limit raised then used to the maximum

- **Signal**: `limit_changed`, `transfer_initiated`
- **Logic**: limit increased, then one or more transfers that use more than 80 percent of the new limit within 2 hours
- **Starting threshold**: as above
- **Known false positives**: customer buying a car or paying fees. Legitimate, but worth a callback for large amounts.
- **Response**: step up or hold
- **Verify**: replay `limit-raise-drain.jsonl`

## DET-BIZ-04 Many transfers just below a control threshold

- **Signal**: `transfer_initiated`
- **Logic**: 5 or more transfers in 24 hours, each within 10 percent below a known control value (step up threshold, daily limit per transaction, reporting threshold)
- **Known false positives**: payroll style bulk payments from business accounts
- **Response**: hand to fraud or AML operations. Do not tip off the customer.
- **Verify**: replay `below-threshold-transfers.jsonl`

## DET-BIZ-05 Idempotency key conflict

- **Signal**: `idempotency_conflict`
- **Logic**: same idempotency key presented with a different amount, destination, or account. A retry has the same payload. A different payload under the same key is an attempt to race or replay.
- **Starting threshold**: 1
- **Known false positives**: client bug that reuses keys. Fix the client.
- **Response**: confirm only one transaction posted. Review the user's other transactions in the same minute.
- **Verify**: send two requests in staging with the same key and different amounts
- **Sigma**: [rules/sigma/det-biz-05-idempotency-conflict.yml](../rules/sigma/det-biz-05-idempotency-conflict.yml)

## DET-BIZ-06 Rejected amounts that only an edited request would send

- **Signal**: `transfer_rejected` or `input_validation_fail` on amount fields
- **Logic**: zero, negative, more than two decimal places, scientific notation, or values above the field maximum. The UI never sends these.
- **Starting threshold**: 2 per user in 1 hour
- **Known false positives**: almost none if the UI validates the same rules
- **Response**: the server rejected it, which is good. Review the user's other requests for tampering.
- **Verify**: replay `tampered-amounts.jsonl`

## DET-BIZ-07 Promotion or reward redemption velocity

- **Signal**: `promo_redeemed` (add this event if your app has rewards, cashback, or referral codes)
- **Logic**: many redemptions per device id across different user ids, or many new accounts created from one device that each redeem a signup bonus
- **Starting threshold**: 3 accounts per device redeeming the same promotion in 7 days
- **Known false positives**: family sharing one phone
- **Response**: claw back per policy. Bind promotions to verified identity, not to account.
- **Verify**: replay `promo-abuse.jsonl`

## Chaining

The strongest account takeover signal in retail banking is a chain, not one event:

1. Login after failures, or from a new device (DET-AUTH-05)
2. Contact detail or MFA device change (DET-BIZ-02, DET-AUTH-07)
3. New beneficiary (DET-BIZ-01)
4. Transfer at or near the limit (DET-BIZ-03)

Each step alone is noisy. Two or more in the same session within a few hours is rarely legitimate. Build a risk score in the SIEM that adds points per step and alerts on the total, instead of alerting on each step.
