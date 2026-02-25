#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# demo.sh — Policy Updating ABE PoC (Docker)
#
# Goal:
#   Run a full end-to-end demo (setup -> keygen -> encrypt -> decrypt ->
#   cloud_update -> decrypt) in a reproducible way.
#
# Usage:
#   bash demo.sh
#
# Optional env vars:
#   IMAGE_TAG=abe-lambda:poc1
#   PROJECT_DIR=/path/to/project          (default: current directory)
#   HOST_KEYS_DIR=/path/to/keys           (default: $PROJECT_DIR/keys)
#   RUN_TESTS=1                           (also run pytest)
#   VERBOSE=1                             (print host paths)
###############################################################################

# ---- Config (edit if needed) ----
IMAGE_TAG="${IMAGE_TAG:-abe-lambda:poc1}"
CURVE="${CURVE:-SS512}"
ELL="${ELL:-10}"

# Policies / attributes used in the demo
POLICY_INIT="${POLICY_INIT:-(attA OR (attB AND attC))}"
ATTRS_USER="${ATTRS_USER:-attA,attB,attC}"

# New policy for cloud update step (keep as your PoC expects)
NEW_POLICY="${NEW_POLICY:-(attA OR (2, attB, attC, attD))}"
TARGET_SUBTREE="${TARGET_SUBTREE:-T1}"
MODE="${MODE:-Attributes2Existing}"

# Project root: default to current directory
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"

# Keys dir on host (default: ./keys)
HOST_KEYS_DIR="${HOST_KEYS_DIR:-$PROJECT_DIR/keys}"

# ---- Helpers ----
say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
die() { printf "\nERROR: %s\n" "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

# Convert a host path to a Docker-friendly path when possible.
# - On Git Bash, cygpath is usually available.
# - On Linux/macOS/WSL, paths are already fine.
to_docker_path() {
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$p"
    return
  fi
  printf "%s" "$p"
}

uuid_from_text() {
  # Extract first UUID from stdin
  grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -n 1
}

run_py_in_container() {
  # Runs python entrypoint without entering container interactively
  # Args: <python_file> <args...>
  local pyfile="$1"; shift
  docker run --rm -i \
    -v "${DOCKER_KEYS_DIR}:/var/task/keys" \
    --entrypoint python "${IMAGE_TAG}" \
    "${pyfile}" "$@"
}

# ---- Preflight ----
need_cmd docker
need_cmd grep

[[ -d "$PROJECT_DIR" ]] || die "PROJECT_DIR not found"

# Ensure keys dir exists
mkdir -p "$HOST_KEYS_DIR"

# Docker mount path
DOCKER_KEYS_DIR="$(to_docker_path "$HOST_KEYS_DIR")"

say "Image tag: $IMAGE_TAG"
if [[ "${VERBOSE:-0}" == "1" ]]; then
  say "Project dir : $PROJECT_DIR"
  say "Keys dir    : $HOST_KEYS_DIR"
  say "Docker mount: $DOCKER_KEYS_DIR -> /var/task/keys"
fi

###############################################################################
# 0) Build image
###############################################################################
say "0) Docker build"
docker build -t "$IMAGE_TAG" "$PROJECT_DIR"

###############################################################################
# 1) Clean old artifacts
###############################################################################
say "1) Clean old artifacts in keys/"
rm -f "$HOST_KEYS_DIR/ta_setup.json" "$HOST_KEYS_DIR/user_sk.json" 2>/dev/null || true
rm -rf "$HOST_KEYS_DIR/store" 2>/dev/null || true
mkdir -p "$HOST_KEYS_DIR/store"

###############################################################################
# 2) Setup
###############################################################################
say "2) Setup (ta_local.py setup)"
run_py_in_container /var/task/ta_local.py setup \
  --curve "$CURVE" \
  --ell "$ELL" \
  --out /var/task/keys/ta_setup.json

[[ -f "$HOST_KEYS_DIR/ta_setup.json" ]] || die "ta_setup.json not found on host. Check volume mount."

###############################################################################
# 3) KeyGen
###############################################################################
say "3) KeyGen (ta_local.py keygen)"
run_py_in_container /var/task/ta_local.py keygen \
  --inp /var/task/keys/ta_setup.json \
  --attrs "$ATTRS_USER" \
  --policy "$POLICY_INIT" \
  --out /var/task/keys/user_sk.json

[[ -f "$HOST_KEYS_DIR/user_sk.json" ]] || die "user_sk.json not found on host. Check volume mount."

###############################################################################
# 4) Encrypt
###############################################################################
say "4) Encrypt (lambda_encrypt.py) — generating object_id"
ENCRYPT_OUT="$(run_py_in_container /var/task/lambda_encrypt.py \
  --setup /var/task/keys/ta_setup.json \
  --policy "$POLICY_INIT" \
  --plaintext "hello world" \
  --store-dir /var/task/keys/store \
  2>&1 | tee /dev/stderr)"

OID="$(printf "%s" "$ENCRYPT_OUT" | uuid_from_text || true)"
[[ -n "${OID:-}" ]] || die "Could not parse object_id (UUID) from encrypt output. Ensure lambda_encrypt.py prints the UUID."

say "Parsed object_id: $OID"

###############################################################################
# 5) Decrypt
###############################################################################
say "5) Decrypt (client_decrypt.py)"
run_py_in_container /var/task/client_decrypt.py \
  --object_id "$OID" \
  --attrs "$ATTRS_USER" \
  --store_dir /var/task/keys/store \
  --setup /var/task/keys/ta_setup.json \
  --sk /var/task/keys/user_sk.json

###############################################################################
# 6) UpKeyGen + CTUpdate (cloud_update.py)
###############################################################################
say "6) Cloud update (cloud_update.py) — update ciphertext policy"
run_py_in_container /var/task/cloud_update.py \
  --setup /var/task/keys/ta_setup.json \
  --store-dir /var/task/keys/store \
  --object-id "$OID" \
  --new-policy "$NEW_POLICY" \
  --target-subtree "$TARGET_SUBTREE" \
  --mode "$MODE"

###############################################################################
# 7) Decrypt again (after update)
###############################################################################
say "7) Decrypt again after update"
run_py_in_container /var/task/client_decrypt.py \
  --object_id "$OID" \
  --attrs "$ATTRS_USER" \
  --store_dir /var/task/keys/store \
  --setup /var/task/keys/ta_setup.json \
  --sk /var/task/keys/user_sk.json

###############################################################################
# Optional: run pytest (if you have requirements-dev.txt and tests/)
###############################################################################
if [[ "${RUN_TESTS:-0}" == "1" ]]; then
  say "Optional) Run pytest inside container (RUN_TESTS=1)"
  docker run --rm -i \
    -e RUN_CHARM_TESTS=1 \
    -v "$(to_docker_path "$PROJECT_DIR"):/work" \
    -w /work \
    --entrypoint /bin/bash \
    "$IMAGE_TAG" \
    -lc "python -m pip install -r requirements-dev.txt && python -m pytest -q -rs"
fi

say "Demo completed. object_id = $OID"
