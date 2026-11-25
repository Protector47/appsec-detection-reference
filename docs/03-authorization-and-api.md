# 3. Authorization and API detections

Broken access control is the most common serious finding in API pentests. Prevention belongs in code (deny by default, object level checks on every handler). Detection is the backstop for the handler someone forgot. These rules depend on `authz_fail` carrying the resource and its owner. If your services only log a status code, fix that first.

## DET-AUTHZ-01 Authorization failure spike for one user

- **Signal**: `authz_fail`
- **Logic**: count `authz_fail` per `user_id` in 10 minutes. Normal users almost never hit a policy deny. A user who hits 20 is probing, or the UI is broken.
- **Starting threshold**: 15 in 10 minutes
- **Known false positives**: front end bug that calls an endpoint the user's role cannot use. Check whether many users show the same `route`.
- **Response**: review the routes and resource ids. If ids are sequential or spread across many owners, escalate as DET-AUTHZ-02.
- **Verify**: replay `object-level-probe.jsonl`
- **Sigma**: [rules/sigma/det-authz-01-authz-fail-spike.yml](../rules/sigma/det-authz-01-authz-fail-spike.yml)

## DET-AUTHZ-02 Object level authorization probe

- **Signal**: `authz_fail` with `resource_id` and `resource_owner`, plus successful reads if you log them (`sensitive_read` or access logs with resource ids)
- **Logic**: one `user_id` touches more than N distinct `resource_owner` values in a window, where the owner is not the user. Failures mean the control works and someone is testing it. Successes mean you have a live broken object level authorization bug.
- **Starting threshold**: 10 distinct foreign owners in 15 minutes. Any success against a foreign owner is critical.
- **Known false positives**: staff or support roles that legitimately read other customers. Exclude them by role and cover them with DET-DATA-02 instead.
- **Response**: on failures, block the user and review. On any success, open an incident, find the handler, and pull every request that hit it.
- **Verify**: replay `object-level-probe.jsonl`

## DET-AUTHZ-03 Cross tenant access attempt

- **Signal**: any event where `tenant_id` of the user differs from the `tenant_id` of the resource
- **Logic**: single event. In a correctly built multi tenant system this should never happen, even as a failure, unless someone crafted the request.
- **Starting threshold**: 1
- **Response**: page the service owner
- **Verify**: send one request in staging with a resource id from another test tenant

## DET-AUTHZ-04 Privileged function used by a non privileged role

- **Signal**: `authz_admin`, `authz_fail` on admin routes
- **Logic**: admin route template (`/admin/*`, `/internal/*`, `/actuator/*`, `/management/*`) called by a session whose role is not in the allowed list. Count both failures and successes.
- **Starting threshold**: 1 for success, 3 in 1 hour for failures
- **Known false positives**: health checks hitting management routes from inside the cluster. Exclude by source network, not by user agent.
- **Response**: success is an incident. Failures need a look at what the user tried.
- **Verify**: replay `admin-route-probe.jsonl`
- **Sigma**: [rules/sigma/det-authz-04-admin-route-non-admin.yml](../rules/sigma/det-authz-04-admin-route-non-admin.yml)

## DET-AUTHZ-05 Role or permission granted

- **Signal**: `authz_change`
- **Logic**: alert on every grant of a privileged role in production, and correlate with a change ticket. Grant to self is critical.
- **Starting threshold**: 1
- **Response**: confirm with the approver named in the ticket. Revoke if there is no ticket.
- **Verify**: grant a test role in UAT, confirm event and alert
- **Sigma**: [rules/sigma/det-authz-05-privileged-role-granted.yml](../rules/sigma/det-authz-05-privileged-role-granted.yml)

## DET-API-01 Mass assignment attempts

- **Signal**: `input_unexpected_field`
- **Logic**: requests carrying fields the endpoint does not accept, especially `role`, `isAdmin`, `balance`, `limit`, `kycStatus`, `ownerId`, `tenantId`. One user sending these repeatedly is testing.
- **Starting threshold**: 3 events with a sensitive field name per user in 1 hour
- **Known false positives**: old mobile app versions sending deprecated fields. Group by `user_agent` and app version.
- **Response**: confirm the API rejected or ignored the field. If the field was accepted anywhere, that is a vulnerability.
- **Verify**: replay `mass-assignment.jsonl`

## DET-API-02 API key used from an unexpected network

- **Signal**: requests authenticated with an API key or client certificate, with `src_ip`
- **Logic**: partner and server to server keys should come from a known IP allowlist or ASN. Alert when a key is used from outside it.
- **Starting threshold**: 1
- **Known false positives**: partner moved hosting provider without telling you
- **Response**: contact the partner on a known channel. Rotate the key if they did not expect it.
- **Verify**: call the staging API with a test key from a non allowlisted host

## DET-API-03 Scraping and bulk enumeration

- **Signal**: access logs with route template and pagination parameters, `data_export`
- **Logic**: one user or key pulls far more records than its own history. Watch for walking pagination to the end on list endpoints, or very high request rates on search endpoints.
- **Starting threshold**: more than 10 times the user's 30 day daily median record count, and at least 1,000 records
- **Known false positives**: month end reporting, finance users exporting statements, a new integration going live
- **Response**: rate limit, then contact the user or integration owner. Check whether the endpoint returns more fields than the UI needs.
- **Verify**: replay `bulk-export.jsonl`

## DET-API-04 Unknown or retired endpoint traffic

- **Signal**: gateway logs with route matched or unmatched
- **Logic**: requests to routes not in the current OpenAPI spec, or to versions you retired (`/v1/` after moving to `/v2/`). Old versions often lack controls added later.
- **Starting threshold**: any successful response from a retired route
- **Response**: confirm the old route is really off. If it answers, remove it or put it behind the same controls.
- **Verify**: compare the gateway's route table with the published spec once per release
