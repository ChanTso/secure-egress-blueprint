# Threat model

## Scope

This model covers the repository's default-disabled infrastructure definition,
host configuration, proxy templates, synthetic client example, traffic guard,
and local validation pipeline. It does not claim control over an adapted
client, a live AWS account, DNS, certificate issuance, the operator's secret
store, or destination services.

## Assets and security objectives

| Asset | Objective |
| --- | --- |
| Tunnel identity and TLS/private key material | Confidentiality, controlled rotation, no Git or log disclosure |
| Fixed egress address | Use only by authorized clients and expected services |
| Destination policy | No access to private, loopback, link-local, metadata-adjacent, or multicast space |
| Client routing | No silent direct fallback in supplied examples |
| Active host configuration | Internally coherent, validated before activation, recoverable after a failed update |
| Infrastructure state | No accidental creation by local examples; no committed state or plans |
| Traffic state | Integrity sufficient for warnings and conservative stop decisions |
| Repository history | No private identifiers, credentials, generated profiles, or inherited production history |

## Actors

- **Authorized maintainer:** reviews source and dependency changes.
- **Authorized operator:** adapts inputs, controls deployment secrets, and owns
  the cloud account and host.
- **Authorized client:** holds a tunnel identity and uses the controlled path.
- **Remote unauthenticated actor:** can reach only allowed public ingress from
  permitted networks.
- **Malicious destination:** observes and responds to egress traffic.
- **Compromised client:** can misuse its own identity and attempt forbidden
  destinations.
- **Compromised service process:** attempts lateral movement or privilege
  escalation on the node.
- **Dependency or contribution adversary:** attempts to insert vulnerable code,
  workflows, secrets, or unsafe examples.
- **Privileged host/account adversary:** controls root or the AWS account.
  This actor is outside the guarantees of the design.

## Threats and mitigations

### T1 — Accidental cloud creation

**Threat:** a reviewer runs a validation command with ambient AWS credentials
and unintentionally creates infrastructure.

**Controls:** infrastructure is conditional on `deployment_enabled`; the default
is false; a distinct sensitive acknowledgement is required when enabled;
local targets omit apply/deploy behavior; default-disabled validation avoids
credential and account lookups.

**Residual risk:** an operator can edit the module or intentionally open the
interlock. Repository controls cannot prevent a privileged, deliberate action.

### T2 — Unauthorized tunnel use

**Threat:** a stolen tunnel identity or overly broad ingress rule permits an
unauthorized party to use the egress node.

**Controls:** narrow, non-world-open TLS CIDRs; per-client synthetic identity
shape; secrets excluded from source; TLS at the public edge.

**Residual risk:** source CIDRs are not identities, and a copied credential
remains usable until rotated. Lightsail also creates a base-OS instance with
default world-open SSH and HTTP rules before the separate public-ports resource
replaces them; this provisioning window is not atomic. A production adaptation
needs an explicit decision on that exposure plus issuance, revocation, and
monitoring procedures outside this repository.

### T3 — Direct-route leakage

**Threat:** when the tunnel fails, the client silently reaches the destination
through its ordinary network.

**Controls:** the supplied synthetic client configuration has the tunnel
outbound and no `freedom`/direct fallback; structural tests reject a direct
outbound.

**Residual risk:** applications, operating systems, DNS, IPv6, or modified
client profiles outside the supplied configuration may choose another route.
Endpoint verification remains necessary.

### T4 — Server-side request forgery or lateral reach

**Threat:** an authorized or compromised client asks the proxy to reach a
private, loopback, link-local, or multicast destination.

**Controls:** explicit Xray routing rules; DNS-aware policy evaluation; a
matching final-IP block in the freedom outbound; structural and negative tests
require both copies of the protected set and their safe ordering.

**Residual risk:** routing engines, DNS behavior, and reserved-address
registries evolve. Cloud-provider service endpoints and public-to-private
rebinding require continuing review. Host root can replace the policy.

### T5 — Exposed internal proxy

**Threat:** Xray is bound publicly, bypassing the Caddy TLS/path boundary.

**Controls:** supplied inbound binds loopback; Caddy's upstream is loopback;
render tests inspect both sides of the relationship; the cloud firewall exposes
only reviewed ports.

**Residual risk:** another host process or a privileged operator can access or
replace a loopback service.

### T6 — Partial or invalid deployment

**Threat:** an interrupted update activates mismatched Caddy/Xray configuration
or leaves services unavailable.

**Controls:** render into staging, validate candidates, restrict permissions,
activate as a coherent set, and use controlled-release recovery logic. A
restored release must pass the same listener and Caddy health checks as a new
activation.
When recovery is unavailable, fail-closed handling stops and disables the
managed unit set and proves it inactive and not boot-enabled before removing
the active pointer. Failure to prove that state keeps the deployment failed.
Static contract tests verify both this fallback and that an already-current
content digest skips pointer and service mutation.

**Residual risk:** power loss, disk failure, package-manager failure, or an
unmodeled service behavior can exceed file-level rollback. This is a single
node; recovery can require manual restoration.

### T7 — Service compromise

**Threat:** a vulnerable proxy process modifies the host or reads unrelated
secrets.

**Controls:** separate service users, restrictive file ownership, normalized
path boundaries, systemd sandboxing, narrow writable paths, and no public Xray
bind. The root guard runs Xray's stats-query subprocess as the fixed `xray`
identity after preflight verifies the executable is root-owned and not
group/world writable.

**Residual risk:** kernel flaws, root-equivalent capabilities, dependencies, or
necessary network access can bypass process hardening.

### T8 — Traffic or cost abuse

**Threat:** an authorized credential, compromised client, or exposed service
generates unexpected traffic and cost.

**Controls:** an optional Lightsail-native five-minute NetworkOut alarm;
local monthly accumulation;
warning threshold; separately acknowledged enforcement; persistent shutdown of
the fixed Caddy/Xray/timer unit set; atomic local state.

**Residual risk:** counters and alarms can lag, reset, omit traffic, or fail.
Enforcement intentionally fails closed on measurement errors, which can cause
an availability loss. Disabling the modeled data plane is not guaranteed to
stop all billable network activity. These controls are not a provider billing
cap.

### T9 — Secret or personal-data disclosure through Git

**Threat:** a contributor commits a credential, real endpoint, state file,
generated client, absolute user path, or binary metadata.

**Controls:** synthetic-only policy, `.gitignore`, privacy lint, Gitleaks,
push protection, code review, and binary/history checks.

**Residual risk:** pattern detection is incomplete. Once a real secret reaches
Git or an artifact, deletion alone is insufficient; rotate it and follow an
incident process.

### T10 — Supply-chain or workflow compromise

**Threat:** a dependency or workflow receives excessive permissions or executes
unreviewed code.

**Controls:** read-only default workflow tokens, reviewed action allowlist and
immutable pinning, CodeQL, dependency review/security updates, protected main,
and required CI.

**Residual risk:** upstream packages, runner images, registries, and GitHub
remain trusted dependencies. A passing scan cannot prove absence of malicious
behavior.

## Abuse cases explicitly not solved

- hiding traffic from AWS, destinations, or a capable observer;
- bypassing sanctions, policy, account restrictions, or destination controls;
- multi-tenant isolation on one node;
- protecting traffic after it leaves the encrypted tunnel;
- controlling a client with local administrator or malware compromise; and
- surviving compromise of host root, the AWS account, or the operator's secret
  system.

## Review triggers

Revisit this model when adding a listener, outbound route, protocol, cloud
resource, secret, service capability, persistent state, identity mechanism,
client platform, dependency with install-time code, or workflow permission.
