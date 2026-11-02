#!/usr/bin/env bash
# Run inside the collector image with bash; no FoD credentials or network access required.
set -euo pipefail
test_dir="$(mktemp -d /tmp/collector-test.XXXXXX)"
trap 'rm -rf "$test_dir"' EXIT
mkdir "$test_dir/bin" "$test_dir/out"
cat >"$test_dir/bin/fcli" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "--version" ]]; then
  echo "fcli version 3.29.0,"
elif [[ "$*" == "fod session login "* ]]; then
  [[ "$*" == *"--scopes view-apps,view-issues"* ]]
elif [[ "$*" == "fod session logout "* ]]; then
  exit 0
elif [[ "$*" == "fod action run "* ]]; then
  action="$4"
  case "$action" in
    */fod-export-inventory.fcli|*/fod-export-findings.fcli) ;;
    *) echo "Unexpected action: $action" >&2; exit 99 ;;
  esac
  [[ "$*" == *"--action-sha256 "* ]]
  [[ "$*" != *"--events-file"* && "$*" != *"--include-system-events"* ]]
  if [[ "${FAIL_FINDINGS:-false}" == true && "$action" == */fod-export-findings.fcli ]]; then
    echo "Simulated findings failure" >&2
    exit 7
  fi
  while (( $# )); do
    case "$1" in
      --applications-file|--releases-file|--file)
        printf '{"coverage":{"fetched_count":0}}\n' >"$2"
        shift ;;
    esac
    shift
  done
else
  echo "Unexpected fcli invocation: $*" >&2
  exit 99
fi
MOCK
chmod +x "$test_dir/bin/fcli"
export PATH="$test_dir/bin:$PATH"
export OUTPUT_DIR="$test_dir/out" FOD_URL=https://example.invalid
export FOD_CLIENT_ID=test FOD_CLIENT_SECRET=test
unset COLLECTORS FOD_SCOPES
bash /opt/collector/bin/collect.sh
COLLECTORS=inventory bash /opt/collector/bin/collect.sh
COLLECTORS=findings WINDOW_DAYS=full bash /opt/collector/bin/collect.sh
code=0
FAIL_FINDINGS=true bash /opt/collector/bin/collect.sh || code=$?
[[ "$code" == 1 ]]
for removed in scans eventlog; do
  code=0
  COLLECTORS="$removed" bash /opt/collector/bin/collect.sh >"$test_dir/error" 2>&1 || code=$?
  [[ "$code" == 2 ]]
  grep -q "supported collectors: inventory,findings" "$test_dir/error"
done
python3 - "$OUTPUT_DIR" <<'CHECK'
import json
import pathlib
import sys

runs = list((pathlib.Path(sys.argv[1]) / "fod").iterdir())
assert len(runs) == 4
observed = set()
for run in runs:
    manifest = json.loads((run / "manifest.json").read_text())
    collectors = manifest["settings"]["collectors"]
    failed = manifest["status"] == "failed"
    observed.add((collectors, failed))
    expected = {"manifest.json"}
    for collector in manifest["collectors"]:
        name = collector["collector"]
        assert name in {"inventory", "findings"}
        files = {"applications.json", "releases.json"} if name == "inventory" else {"findings.json"}
        if failed and name == "findings":
            assert collector["exit_code"] == 7 and collector["outputs"] == []
        else:
            assert collector["status"] == "succeeded"
            assert {output["file"] for output in collector["outputs"]} == files
            expected.update(files)
    assert {path.name for path in run.iterdir()} == expected
    assert not any("event" in key or "history" in key for key in manifest["settings"])
assert observed == {("inventory,findings", False), ("inventory", False),
                    ("findings", False), ("inventory,findings", True)}
print("PASS: default/subset outputs, full window, failure manifest, removed collectors")
CHECK
