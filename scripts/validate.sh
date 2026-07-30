#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: $0" >&2
  exit 64
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
cd "$repository_root"

ruff check .
ruff format --check .
python3 -m compileall -q src tests
pytest --cov --cov-report=term-missing
shellcheck scripts/*.sh
yamllint ansible .github
ansible-playbook --syntax-check \
  -i ansible/inventory.example.yml \
  ansible/deploy.yml
ansible-lint ansible
tofu fmt -check -recursive infra/tofu
"$script_dir/validate-tofu-offline.sh"
python3 -m secure_egress.privacy_lint .
gitleaks git . --redact=100 --no-banner
python3 -m build --no-isolation

