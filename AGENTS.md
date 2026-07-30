# Repository-wide agent rules

- Never add real domains, public IP addresses, cloud account identifiers, UUIDs,
  credentials, device labels, or infrastructure names.
- Every fixture and example must be visibly synthetic and use reserved
  documentation values.
- Local validation must not contact cloud APIs, read remote state, or make
  infrastructure changes.
- Never push directly to `main`; use a pull request.
- A sandboxed `gh auth status` failure can be a false negative. Recheck outside
  the restricted sandbox before requesting authentication.
- Changes to infrastructure-as-code must update the relevant tests,
  architecture documentation, and threat model.

