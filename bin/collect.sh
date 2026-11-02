#!/usr/bin/env bash
# One-shot FoD data collection run; see README.md for configuration.
set -euo pipefail
OUTPUT_UMASK="${OUTPUT_UMASK:-027}"
[[ "$OUTPUT_UMASK" =~ ^0?[0-7]{3}$ ]] || { echo "OUTPUT_UMASK must be an octal value like 027" >&2; exit 2; }
umask "$OUTPUT_UMASK"

COLLECTOR_HOME="${COLLECTOR_HOME:-/opt/collector}"
ACTIONS_DIR="${COLLECTOR_HOME}/actions"
OUTPUT_DIR="${OUTPUT_DIR:-/data/out}"
COLLECTORS="${COLLECTORS:-inventory,findings}"
WINDOW_DAYS="${WINDOW_DAYS:-2}"
INVENTORY_MODE="${INVENTORY_MODE:-full}"
SCAN_TYPE="${SCAN_TYPE:-All}"
SEVERITIES="${SEVERITIES:-Critical,High}"
RELEASE_FILTERS="${RELEASE_FILTERS:-}"
SOURCE_INSTANCE_ID="${SOURCE_INSTANCE_ID:-}"
FCLI_LOG_LEVEL="${FCLI_LOG_LEVEL:-}"
ACTION_PUBKEY="${ACTION_PUBKEY:-}"
FOD_SCOPES="${FOD_SCOPES:-api-tenant}"
FOD_SESSION="collector"

log() { printf '%s [collector] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
fail() { log "ERROR: $*"; exit 2; }

# Reads NAME or NAME_FILE (Docker/Kubernetes secrets); both set is an error.
read_secret() {
  local name="$1" file_var="${1}_FILE"
  local value="${!name:-}" file="${!file_var:-}"
  if [[ -n "$value" && -n "$file" ]]; then fail "Set either ${name} or ${file_var}, not both"; fi
  if [[ -n "$file" ]]; then
    [[ -r "$file" ]] || fail "${file_var} is not readable"
    # Tolerate secret files written on Windows (UTF-8 BOM, CRLF line endings).
    value="$(head -n 1 "$file" | tr -d '\r')"
    value="${value#$'\xEF\xBB\xBF'}"
  fi
  printf '%s' "$value"
}

FOD_URL="$(read_secret FOD_URL)"
FOD_CLIENT_ID="$(read_secret FOD_CLIENT_ID)"
FOD_CLIENT_SECRET="$(read_secret FOD_CLIENT_SECRET)"
FOD_TENANT="$(read_secret FOD_TENANT)"
FOD_USER="$(read_secret FOD_USER)"
FOD_PAT="$(read_secret FOD_PAT)"

[[ "$FOD_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] || fail "FOD_URL must be an https:// base URL"
if [[ "$WINDOW_DAYS" == "full" ]]; then
  WINDOW_ARGS=()
elif [[ "$WINDOW_DAYS" =~ ^[0-9]+$ ]] && (( WINDOW_DAYS <= 30 )); then
  WINDOW_ARGS=(--window-days "$WINDOW_DAYS")
else
  fail "WINDOW_DAYS must be an integer between 0 and 30, or 'full'"
fi
[[ "$INVENTORY_MODE" == "full" || "$INVENTORY_MODE" == "window" ]] || fail "INVENTORY_MODE must be 'full' or 'window'"
[[ "$SCAN_TYPE" =~ ^[A-Za-z][A-Za-z0-9]{0,63}$ ]] || fail "SCAN_TYPE is invalid"
[[ "$SEVERITIES" =~ ^[A-Za-z_]+(,[A-Za-z_]+)*$ ]] || fail "SEVERITIES is invalid"
[[ "$SOURCE_INSTANCE_ID" =~ ^[A-Za-z0-9._:-]{0,128}$ ]] || fail "SOURCE_INSTANCE_ID is invalid"
[[ "$FOD_SCOPES" =~ ^[a-z-]+(,[a-z-]+)*$ ]] || fail "FOD_SCOPES is invalid"
for c in ${COLLECTORS//,/ }; do
  [[ "$c" =~ ^(inventory|findings)$ ]] || fail "Unknown collector '$c'; supported collectors: inventory,findings"
done
[[ -d "$OUTPUT_DIR" && -w "$OUTPUT_DIR" ]] || fail "OUTPUT_DIR ${OUTPUT_DIR} must be a writable mounted directory"

# Validates classifiers and selection settings and exports COLLECTOR_* variables read by the actions.
CONFIG_FILE="$(mktemp /tmp/collector-config.XXXXXX)"
python3 "${COLLECTOR_HOME}/bin/prepare_config.py" >"$CONFIG_FILE" || { rm -f "$CONFIG_FILE"; exit 2; }
while IFS= read -r -d '' pair; do
  export "${pair%%=*}=${pair#*=}"
done <"$CONFIG_FILE"
rm -f "$CONFIG_FILE"

# Baked actions are integrity-checked; signatures are enforced only when a public key is supplied.
(cd "$ACTIONS_DIR" && sha256sum --quiet -c "${COLLECTOR_HOME}/actions.sha256") || fail "Action integrity check failed"
if [[ -n "$ACTION_PUBKEY" ]]; then
  SIGNATURE_ARGS=(--pubkey "file:${ACTION_PUBKEY}" --on-unsigned=fail --on-invalid-signature=fail --on-no-public-key=fail)
else
  SIGNATURE_ARGS=(--on-unsigned=ignore --on-invalid-signature=fail --on-no-public-key=warn)
fi
action_hash() { awk -v f="$1" '$2 == f || $2 == "*"f {print $1}' "${COLLECTOR_HOME}/actions.sha256"; }

export FCLI_USER_HOME="${FCLI_USER_HOME_OVERRIDE:-$(mktemp -d /tmp/fcli-home.XXXXXX)}"
RUN_ID="$(cat /proc/sys/kernel/random/uuid)"
RUN_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_NAME="$(date -u +%Y%m%dT%H%M%SZ)-${RUN_ID}"
mkdir -p "${OUTPUT_DIR}/fod"
WORK_DIR="${OUTPUT_DIR}/fod/.partial-${RUN_NAME}"
FINAL_DIR="${OUTPUT_DIR}/fod/${RUN_NAME}"
mkdir "$WORK_DIR"
STATUS_FILE="$(mktemp /tmp/collector-status.XXXXXX)"

cleanup() {
  fcli fod session logout --fod-session "$FOD_SESSION" >/dev/null 2>&1 || true
  rm -rf "$FCLI_USER_HOME" "$STATUS_FILE"
  # Only present if the run aborted before the final rename.
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log "Run ${RUN_ID}: collectors=${COLLECTORS} window=${WINDOW_DAYS}"
if [[ -n "$FOD_CLIENT_ID" ]]; then
  [[ -n "$FOD_CLIENT_SECRET" ]] || fail "FOD_CLIENT_SECRET is required with FOD_CLIENT_ID"
  FCLI_DEFAULT_FOD_CLIENT_SECRET="$FOD_CLIENT_SECRET" fcli fod session login --url "$FOD_URL" \
    --client-id "$FOD_CLIENT_ID" --scopes "$FOD_SCOPES" --fod-session "$FOD_SESSION" >/dev/null \
    || fail "FoD login failed"
elif [[ -n "$FOD_USER" ]]; then
  [[ -n "$FOD_TENANT" && -n "$FOD_PAT" ]] || fail "FOD_TENANT and FOD_PAT are required with FOD_USER"
  FCLI_DEFAULT_FOD_PASSWORD="$FOD_PAT" fcli fod session login --url "$FOD_URL" \
    --tenant "$FOD_TENANT" --user "$FOD_USER" --scopes "$FOD_SCOPES" --fod-session "$FOD_SESSION" >/dev/null \
    || fail "FoD login failed"
else
  fail "Provide FOD_CLIENT_ID/FOD_CLIENT_SECRET or FOD_TENANT/FOD_USER/FOD_PAT"
fi
unset FOD_CLIENT_SECRET FOD_PAT

COMMON_ARGS=()
[[ -n "$SOURCE_INSTANCE_ID" ]] && COMMON_ARGS+=(--source-instance "$SOURCE_INSTANCE_ID")

# Resolve the release scope once so every collector uses the same release set.
SCOPE_ARGS=()
if [[ -n "$RELEASE_FILTERS" || -n "$COLLECTOR_RELEASE_QUERY" || -n "$COLLECTOR_APPLICATION_QUERY" ]]; then
  release_query="$COLLECTOR_RELEASE_QUERY"
  if [[ -n "$COLLECTOR_APPLICATION_QUERY" ]]; then
    fcli fod app list --fod-session "$FOD_SESSION" --store collector_scope_apps -o 'expr={applicationId}\n' >/dev/null || fail "Listing applications failed"
    app_ids="$(fcli util variable contents collector_scope_apps -q "$COLLECTOR_APPLICATION_QUERY" -o 'expr={applicationId},')" \
      || fail "APPLICATION_QUERY/APPLICATION_ATTRIBUTES could not be evaluated"
    app_ids="${app_ids%,}"
    [[ -n "$app_ids" ]] || fail "No applications match APPLICATION_QUERY/APPLICATION_ATTRIBUTES"
    app_cond="{${app_ids}}.contains(applicationId)"
    release_query="${release_query:+(${release_query}) && }${app_cond}"
  fi
  scope_cmd=(fcli fod release list --fod-session "$FOD_SESSION" --store collector_scope -o 'expr={releaseId}\n')
  [[ -n "$RELEASE_FILTERS" ]] && scope_cmd+=(--filters-param "$RELEASE_FILTERS")
  [[ -n "$release_query" ]] && scope_cmd+=(-q "$release_query")
  scope_count="$("${scope_cmd[@]}" | grep -c . || true)"
  (( scope_count > 0 )) || fail "Release selection resolved to zero releases"
  log "Release selection resolved to ${scope_count} releases"
  SCOPE_ARGS=(--scope-var collector_scope)
  [[ -n "$RELEASE_FILTERS" ]] && SCOPE_ARGS+=(--release-filters "$RELEASE_FILTERS")
  [[ -n "$COLLECTOR_RELEASE_QUERY" ]] && SCOPE_ARGS+=(--release-query "$COLLECTOR_RELEASE_QUERY")
  [[ -n "$COLLECTOR_APPLICATION_QUERY" ]] && SCOPE_ARGS+=(--application-query "$COLLECTOR_APPLICATION_QUERY")
fi

run_action() {
  local collector="$1" action="$2"; shift 2
  local log_args=()
  [[ -n "$FCLI_LOG_LEVEL" ]] && log_args=(--log-level "$FCLI_LOG_LEVEL" --log-file "${WORK_DIR}/logs/${collector}.log")
  [[ -n "$FCLI_LOG_LEVEL" ]] && mkdir -p "${WORK_DIR}/logs"
  fcli fod action run "${ACTIONS_DIR}/${action}" "${SIGNATURE_ARGS[@]}" --progress=stderr \
    --fod-session "$FOD_SESSION" "${log_args[@]}" --action-sha256 "$(action_hash "$action")" "$@"
}

overall=0
record() {
  local collector="$1" code="$2" started="$3" files="$4"
  printf '%s\t%s\t%s\t%s\t%s\n' "$collector" "$code" "$started" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$files" >>"$STATUS_FILE"
  if [[ "$code" != "0" ]]; then overall=1; log "Collector ${collector} failed with exit code ${code}"; fi
}

for collector in ${COLLECTORS//,/ }; do
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "Starting collector ${collector}"
  code=0
  case "$collector" in
    inventory)
      inv_args=()
      [[ "$INVENTORY_MODE" == "window" ]] && inv_args=("${WINDOW_ARGS[@]}")
      run_action inventory fod-export-inventory.fcli "${COMMON_ARGS[@]}" "${SCOPE_ARGS[@]}" "${inv_args[@]}" \
        --applications-file "${WORK_DIR}/applications.json" --releases-file "${WORK_DIR}/releases.json" || code=$?
      record inventory "$code" "$started" "applications.json,releases.json"
      ;;
    findings)
      run_action findings fod-export-findings.fcli "${COMMON_ARGS[@]}" "${SCOPE_ARGS[@]}" "${WINDOW_ARGS[@]}" \
        --scan-type "$SCAN_TYPE" --severities "$SEVERITIES" --file "${WORK_DIR}/findings.json" || code=$?
      record findings "$code" "$started" "findings.json"
      ;;
  esac
done

SETTINGS_JSON="$(COLLECTORS="$COLLECTORS" WINDOW_DAYS="$WINDOW_DAYS" INVENTORY_MODE="$INVENTORY_MODE" SCAN_TYPE="$SCAN_TYPE" \
  SEVERITIES="$SEVERITIES" RELEASE_FILTERS="$RELEASE_FILTERS" SOURCE_INSTANCE_ID="$SOURCE_INSTANCE_ID" \
  FOD_URL="$FOD_URL" \
  RELEASE_QUERY="$COLLECTOR_RELEASE_QUERY" APPLICATION_QUERY="$COLLECTOR_APPLICATION_QUERY" \
  CLASSIFIER_MODE="$COLLECTOR_CLASSIFIER_MODE" CLASSIFIERS="$COLLECTOR_CLASSIFIERS_JSON" \
  python3 -c 'import json,os; k=["COLLECTORS","WINDOW_DAYS","INVENTORY_MODE","SCAN_TYPE","SEVERITIES","RELEASE_FILTERS","RELEASE_QUERY","APPLICATION_QUERY","SOURCE_INSTANCE_ID","CLASSIFIER_MODE","CLASSIFIERS","FOD_URL"]; print(json.dumps({x.lower(): (os.environ.get(x) or None) for x in k}))')"
python3 "${COLLECTOR_HOME}/bin/write_manifest.py" --run-dir "$WORK_DIR" --status-file "$STATUS_FILE" \
  --settings "$SETTINGS_JSON" --run-id "$RUN_ID" --started-at "$RUN_STARTED" \
  --fcli-version "$(fcli --version | awk '{print $3}' | tr -d ,)" --collector-version "${COLLECTOR_VERSION:-}"
mv "$WORK_DIR" "$FINAL_DIR"
log "Run ${RUN_ID} finished with status $([[ $overall == 0 ]] && echo succeeded || echo failed): ${FINAL_DIR}"
exit "$overall"
