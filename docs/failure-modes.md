# Failure modes

Fail-closed systems trade some availability for a bounded failure outcome.
This document states the expected behavior of the reference implementation and
the residual operator responsibility.

| Failure | Expected behavior | Security outcome | Recovery owner |
| --- | --- | --- | --- |
| Tunnel unreachable | Supplied client profile has no direct fallback | Protected traffic is denied rather than intentionally routed direct | Client/operator |
| Invalid client profile | Structural test rejects missing tunnel or direct fallback | Invalid synthetic artifact is not accepted by tests | Maintainer |
| Caddy candidate invalid | Validation fails before the current pointer changes | Active pointer and services remain untouched | Operator |
| Xray candidate invalid | Validation fails before the current pointer changes | Active pointer and services remain untouched | Operator |
| Service restart or post-switch health check fails | Previous release is restored, restarted, and health-checked; without a verified recovery, managed units must be proved inactive and not boot-enabled before the pointer is removed | Availability may be lost; inability to prove closure keeps the deployment failed | Operator |
| Unknown public path | Caddy returns not found | Node is not a general public web/proxy endpoint | Automatic |
| Xray public bind introduced | Render/structural test fails | Change cannot pass the expected quality gate | Maintainer |
| Private/link-local destination requested | Xray routes request to blocked outbound | Requested connection is denied | Automatic |
| DNS resolves into a blocked range | DNS-aware routing and the freedom outbound's final-IP rule evaluate the protected set | Requested connection should be denied by supplied policy | Automatic |
| Certificate expires or renewal fails | New TLS sessions fail | Egress becomes unavailable; no client direct fallback is added | Operator |
| New Lightsail instance is provisioning | Default SSH/HTTP firewall rules can be world-open until the public-ports resource converges | Transient ingress is broader than the final model | Operator chooses another compute primitive if unacceptable |
| Node or availability zone fails | Egress stops | No automatic failover; fixed source is unavailable | Operator |
| Static address is replaced | Downstream allowlists may no longer match | Access fails or requires separately approved update | Operator |
| Metrics/config unavailable or malformed in decision-only mode | Guard reports an error and does not mutate services | Existing service state is unchanged | Operator |
| Metrics/config unavailable or malformed with enforcement armed | Guard persistently disables the fixed Caddy/Xray/timer set | Egress fails closed; availability is lost | Operator |
| Counter resets | Accumulator treats the new value as post-reset traffic | Estimate continues but may differ from provider billing | Operator |
| Warning threshold reached | Guard reports warning | Traffic continues unless a separate stop policy is armed | Operator |
| Stop threshold reached in dry-run | Guard reports warning/decision only | No service mutation | Operator |
| Stop threshold reached with both interlocks | The fixed Caddy/Xray/timer set is stopped and disabled | Tunnel egress remains unavailable across reboot until authorized recovery | Operator |
| Guard state write interrupted | Atomic replacement preserves old or new file | State may be stale; it should not become partially written | Operator |
| Lightsail alarm or regional contact delivery fails | Notification may be absent | Traffic and cost may continue | Operator |
| Secret appears in Git | Scanners may block or report it | Confidentiality must be treated as lost | Maintainer rotates secret |
| Host root or AWS account compromised | Adversary can alter services, policy, logs, or resources | Repository guarantees no longer apply | Incident owner |

## Recovery principles

1. Prefer the last known coherent configuration over a partially rendered set.
2. Do not weaken routing or open ingress to restore availability.
3. Re-run local/static validation before an authorized recovery change.
4. Treat credentials and generated clients as compromised if their
   confidentiality is uncertain; revoke and rotate them.
5. Compare traffic and charges with provider-authoritative data. Local state is
   advisory.
6. Preserve incident evidence without committing logs, state, identifiers, or
   secrets to this repository.
7. Revisit the threat model after any failure that contradicts this table.

## What fail-closed does not cover

Fail-closed behavior is bounded to the supplied configuration and modeled
services. It cannot stop an application from using an unrelated network
interface, a modified client from adding a direct route, root from changing the
server, or an account administrator from replacing infrastructure. Platform-
specific leak tests and operational controls remain necessary.
