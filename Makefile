SHELL := /bin/sh
.DEFAULT_GOAL := help

.PHONY: help install lint test templates tofu-fmt tofu-validate yaml ansible-check shellcheck privacy gitleaks build verify

help:
	@echo "Safe local targets only:"
	@echo "  install         Install the pinned development toolchain"
	@echo "  lint            Run Python lint and compile checks"
	@echo "  test            Run unit and template tests"
	@echo "  tofu-fmt        Check OpenTofu formatting"
	@echo "  tofu-validate   Validate initialized OpenTofu modules without state access"
	@echo "  yaml            Lint Ansible and GitHub YAML"
	@echo "  ansible-check   Run Ansible syntax and lint checks"
	@echo "  shellcheck      Check shell scripts"
	@echo "  privacy         Enforce synthetic-example policy"
	@echo "  gitleaks        Scan the local Git history"
	@echo "  build           Build the Python package"
	@echo "  verify          Run every local quality gate"

install:
	python3 -m pip install --editable '.[dev]'

lint:
	ruff check .
	ruff format --check .
	python3 -m compileall -q src tests

test:
	pytest --cov --cov-report=term-missing

templates:
	pytest -q tests/templates

tofu-fmt:
	tofu fmt -check -recursive infra/tofu

tofu-validate:
	./scripts/validate-tofu-offline.sh

yaml:
	yamllint ansible .github

ansible-check:
	ansible-playbook --syntax-check -i ansible/inventory.example.yml ansible/deploy.yml
	ansible-lint ansible

shellcheck:
	shellcheck scripts/*.sh

privacy:
	python3 -m secure_egress.privacy_lint .

gitleaks:
	gitleaks git . --redact=100 --no-banner

build:
	python3 -m build

verify: lint test tofu-fmt tofu-validate yaml ansible-check shellcheck privacy gitleaks build

