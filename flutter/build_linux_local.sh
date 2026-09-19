#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: this script only supports Linux" >&2
    exit 1
fi

: "${VCPKG_ROOT:?ERROR: VCPKG_ROOT is not set}"

if [[ ! -x "${VCPKG_ROOT}/vcpkg" ]]; then
    echo "ERROR: vcpkg executable not found: ${VCPKG_ROOT}/vcpkg" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) VCPKG_TARGET="${VCPKG_TARGET:-x64-linux}" ;;
    aarch64 | arm64) VCPKG_TARGET="${VCPKG_TARGET:-arm64-linux}" ;;
    *)
        echo "ERROR: unsupported Linux architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

export VCPKG_INSTALLED_ROOT="${VCPKG_INSTALLED_ROOT:-${VCPKG_ROOT}/installed-linux}"

if [[ "$(realpath -m "${VCPKG_INSTALLED_ROOT}")" == "$(realpath -m "${VCPKG_ROOT}/installed")" ]]; then
    echo "ERROR: Linux must not use the shared vcpkg installed directory" >&2
    exit 1
fi

echo "INFO: Linux vcpkg installed root: ${VCPKG_INSTALLED_ROOT}"

"${VCPKG_ROOT}/vcpkg" install \
    --triplet "${VCPKG_TARGET}" \
    --x-install-root="${VCPKG_INSTALLED_ROOT}" \
    --x-manifest-root="${REPO_ROOT}"

if [[ "${1:-}" == "--deps-only" ]]; then
    exit 0
fi

cd "${REPO_ROOT}"
exec python3 build.py --flutter "$@"
