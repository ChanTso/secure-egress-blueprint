# Contributing

Contributions that improve safety, clarity, tests, or portability are welcome.
This repository treats privacy and offline validation as acceptance criteria,
not optional cleanup.

## Ground rules

- Use only `example.com` subdomains, RFC 5737 IPv4 ranges, reserved synthetic
  UUIDs, and clearly fictional account and device labels.
- Never commit credentials, private deployment output, state, plans, generated
  client bundles, QR codes, logs, or real infrastructure identifiers.
- Do not add commands that create, change, inspect, or destroy live cloud or
  network resources to examples or local validation.
- Keep deployment disabled by default. Any new side effect needs an explicit
  interlock, validation, and rollback behavior.
- Do not add a direct client fallback. Failure of the protected path must deny
  egress.
- Update tests, architecture documentation, and the threat model when an
  infrastructure or trust-boundary change is proposed.
- Do not push directly to `main`; open a pull request.

## Local setup

Python 3.11 or newer is required for the validation utilities. Install
development dependencies in an isolated environment:

```console
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --editable '.[dev]'
```

Install OpenTofu, Ansible tooling, ShellCheck, and Gitleaks from their official
distribution channels. Installation is intentionally not automated because
platform trust policies differ.

## Safe validation

The aggregate target is designed for local/static checks and must not use cloud
credentials or remote state:

```console
make verify
```

Individual targets are listed by `make help`. Backend-disabled OpenTofu
initialization may fetch only the lockfile-pinned provider when it is not
already installed. The validate phase uses dead proxies and cleared credential
selectors. A check that needs cloud credentials, remote state, or a real
endpoint does not belong in `make verify`.

## Pull requests

Keep changes focused and explain:

1. the problem and security property being changed;
2. the evidence supplied by tests or static checks;
3. any change to a trust boundary or failure mode; and
4. the synthetic fixtures used for validation.

Pull requests must pass the required `Test` check, resolve review discussions,
and preserve a linear history. Dependencies should not be auto-merged without
the same validation as code changes.

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE).
