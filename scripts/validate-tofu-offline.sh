#!/bin/sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "usage: $0" >&2
  echo "This validator accepts no subcommand or remote-state arguments." >&2
  exit 64
fi

if ! command -v tofu >/dev/null 2>&1; then
  echo "OpenTofu is required for local validation." >&2
  exit 127
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
module_dir="$repository_root/infra/tofu"

export TF_IN_AUTOMATION=1
export TF_INPUT=0
export AWS_EC2_METADATA_DISABLED=true
unset TF_CLI_ARGS
unset TF_CLI_ARGS_init
unset TF_CLI_ARGS_validate

run_safe_tofu()
{
  subcommand=$1
  shift
  case "$subcommand" in
    init | validate)
      ;;
    *)
      echo "Blocked non-validation OpenTofu subcommand." >&2
      exit 65
      ;;
  esac
  tofu "-chdir=$module_dir" "$subcommand" "$@"
}

# Backend initialization is explicitly disabled. A first run may download only
# the provider version already pinned in the committed dependency lock file.
run_safe_tofu init -backend=false -input=false -lockfile=readonly

# Validation executes with no credential selectors, no shared credential files,
# and dead network proxies. Unexpected provider access therefore fails closed.
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset AWS_SECURITY_TOKEN
unset AWS_PROFILE
unset AWS_DEFAULT_PROFILE
unset AWS_WEB_IDENTITY_TOKEN_FILE
unset AWS_ROLE_ARN
unset AWS_ROLE_SESSION_NAME
unset AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
unset AWS_CONTAINER_CREDENTIALS_FULL_URI
unset AWS_CONTAINER_AUTHORIZATION_TOKEN
unset AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null
export AWS_SDK_LOAD_CONFIG=0
export HTTP_PROXY=http://127.0.0.1:9
export HTTPS_PROXY=http://127.0.0.1:9
export ALL_PROXY=http://127.0.0.1:9
export http_proxy=http://127.0.0.1:9
export https_proxy=http://127.0.0.1:9
export all_proxy=http://127.0.0.1:9
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

run_safe_tofu validate -no-color

