#!/bin/bash

# Load repo-local environment variables for scripts without requiring callers to source .env.
_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PA3_CODE_ROOT="$(cd "${_script_dir}/.." && pwd)"
PA3_ENV_FILE="${PA3_ENV_FILE:-${PA3_CODE_ROOT}/.env}"

if [[ -f "${PA3_ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${PA3_ENV_FILE}"
    set +a
fi

: "${PA3_REPO_ROOT:?Set PA3_REPO_ROOT in ${PA3_ENV_FILE} or export it before running this script}"
