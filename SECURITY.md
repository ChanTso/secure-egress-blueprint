# Security policy

## Supported versions

This project is a reference implementation, not a managed service. Security
fixes are applied to the default branch. No long-term support branches are
currently maintained.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** feature on the repository
Security tab. Do not open a public issue for a suspected vulnerability, leaked
credential, or privacy finding.

Include:

- the affected file, component, and revision;
- a minimal reproduction using synthetic data only;
- the security impact and preconditions;
- any suggested mitigation; and
- whether disclosure has already occurred elsewhere.

Do not include live credentials, private keys, non-documentation IP addresses,
personal data, or identifiers from a real deployment. Maintainers will
acknowledge a complete report when practical, investigate it, and coordinate a
fix and disclosure. This repository does not offer a bug bounty or guaranteed
response time.

## Scope

Reports about the following are useful:

- bypasses of the default deployment interlock;
- routes that permit direct client fallback or access to private destinations;
- services that unexpectedly listen beyond loopback;
- unsafe secret placement, file permissions, or log disclosure;
- deployment rollback or partial-activation failures;
- command injection or privilege-boundary violations;
- privacy-lint or secret-scanning bypasses; and
- vulnerable workflow permissions or dependency pinning.

The following are architectural limitations rather than vulnerabilities:

- the reference topology is a single node and is not highly available;
- it does not provide anonymity against AWS, the destination, or a global
  observer;
- traffic alarms and the traffic guard are not billing caps;
- an authorized operator can deliberately replace the safe defaults; and
- availability failures may intentionally deny egress.

See [Security model](docs/security-model.md) and
[Threat model](docs/threat-model.md) before reporting an issue.

## Operational responsibility

Never test against systems you do not own or have explicit authorization to
assess. A real deployment requires an independent review of identity, network,
DNS, certificate, logging, cost, backup, recovery, and applicable legal
requirements. This repository's local validation commands are designed not to
contact cloud APIs; a deployment workflow is intentionally outside their
scope.
