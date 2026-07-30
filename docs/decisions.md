# Architecture decisions

This record summarizes the decisions that define the public reference. A change
to one of these decisions should update its tests, architecture, and threat
model in the same pull request.

## ADR-001 — Default to zero managed resources

**Status:** accepted

**Decision:** keep resource creation behind a false-by-default variable and a
separate explicit acknowledgement.

**Why:** a public IaC example can be evaluated in an environment with ambient
credentials. Formatting and validation must not imply permission to create or
inspect live resources.

**Consequences:** local evaluation is safer and deterministic. An authorized
adopter must design a separate, reviewed deployment process.

## ADR-002 — Prefer one retained static address over automatic failover

**Status:** accepted

**Decision:** model one IPv4-only Lightsail node and one attached static IPv4
address with destruction protection. IPv6 is intentionally disabled so modeled
egress cannot bypass the retained source address.

**Why:** the primary requirement is a small, understandable set of stable source
addresses. Automatic replacement or multi-node failover can unexpectedly
change that set and enlarge the security review surface.

**Consequences:** the node and availability zone are single points of failure.
This project does not claim high availability.

## ADR-003 — Put Caddy at the only public application boundary

**Status:** accepted

**Decision:** terminate public TLS in Caddy and keep the Xray inbound on
loopback. Proxy only the selected path and reject unknown paths.

**Why:** separating public TLS from tunnel policy gives each service a narrow
role and makes the public-to-local transition testable.

**Consequences:** both configurations must change coherently. Loopback does not
protect against root or a compromised local process.

## ADR-004 — Make the supplied client fail closed

**Status:** accepted

**Decision:** omit a direct/freedom outbound from the synthetic client profile.

**Why:** silently changing source identity when the tunnel fails defeats the
fixed-egress security property.

**Consequences:** tunnel, TLS, DNS, or node failures deny protected traffic.
Availability is lower, and each real client platform still needs leak testing.

## ADR-005 — Deny protected address classes at the server

**Status:** accepted

**Decision:** resolve domains as needed for routing policy, then apply the same
protected-address set again at the freedom outbound's final connection check.
Block private, loopback, link-local, carrier-grade NAT, multicast, and analogous
IPv6 destinations. Require an Xray version that supports final outbound rules.

**Why:** tunnel authentication alone must not turn the node into a path to
internal or special-purpose networks.

**Consequences:** the deny set needs maintenance and cannot replace
organization-specific destination policy.

## ADR-006 — Activate host configuration transactionally

**Status:** accepted

**Decision:** stage a coherent candidate set, validate it with the real Caddy
and Xray parsers, then activate and recover toward the previous set on a
detected failure. A restored set must pass the same listener and health checks
as a new activation. Local render tests separately inspect cross-template
structural relationships.

**Why:** updating Caddy and Xray files independently can produce a valid
individual file but an invalid service relationship.

**Consequences:** the Ansible implementation and failure-path tests are more
complex. File-level recovery cannot survive every host or storage failure.

## ADR-007 — Keep secrets and generated clients outside Git

**Status:** accepted

**Decision:** commit schemas, templates, and synthetic fixtures only. An
operator-selected mechanism supplies real secrets at execution time and
distributes generated clients separately.

**Why:** Git history, CI artifacts, forks, and logs are poor revocation
boundaries.

**Consequences:** the public reference cannot be a one-command deployment.
Adopters own secret issuance, storage, delivery, rotation, and incident
response.

## ADR-008 — Treat traffic controls as safeguards, not accounting

**Status:** accepted

**Decision:** keep traffic decisions deterministic and side-effect-free by
default. Require separate policy and command interlocks before persistently
stopping and disabling the fixed Caddy, Xray, and guard-timer set. When
enforcement is armed, measurement or configuration errors also fail closed.

**Why:** local counters can support rapid defensive action but are not
provider-authoritative billing data.

**Consequences:** measurement gaps and delayed charges remain possible.
Enforcement can intentionally trade availability for containment, and an
authorized recovery must re-enable the units. The operator must still compare
against provider billing and alarm systems.
