# Fortify 

A self-contained, one-shot Docker container that collects application/release inventory and findings from Fortify on Demand (FoD) using versioned fcli actions. It writes JSON documents to a mounted directory. The output contract is documented in [schema/README.md](schema/README.md).

Each default run produces `applications.json`, `releases.json`, `findings.json` and `manifest.json`. Scan collections, issue-history events and tenant event logs are no longer collected. Rebuild the image to apply this change; remove `scans` and `eventlog` from any explicit `COLLECTORS` setting.

Scheduling is out of scope: start the container from cron, a Kubernetes CronJob, or a CI pipeline.

## Contents

| Path | Purpose |
|---|---|
| [actions/](actions/) | fcli actions: `fod-export-inventory`, `fod-export-findings`. |
| [classifiers/](classifiers/) | Built-in finding classifiers (YAML). |
| [bin/collect.sh](bin/collect.sh) | Container entrypoint: validate config, login, resolve scope, run the collectors, write the manifest, logout. |
| [bin/prepare_config.py](bin/prepare_config.py) | Validates classifier files and selection settings. |
| [bin/Set-CollectorEnv.ps1](bin/Set-CollectorEnv.ps1) | Loads classifier variables into a PowerShell session for running the actions without the container. |
| [schema/](schema/) | JSON Schemas and contract documentation. |
| [examples/run/](examples/run/) | Synthetic run output. |
| [tools/validate_output.py](tools/validate_output.py) | Validates output against the schemas. |

## Build

```powershell
docker build -t fcli-data-collector:1.0.0 .
# Use a different fcli base image:
docker build --build-arg FCLI_IMAGE=fortifydocker/fcli:3-ubi9 -t fcli-data-collector:1.0.0 .
```

The image is based on `fortifydocker/fcli:<version>-ubi9`, runs as UID 10001, and verifies the SHA-256 of the bundled actions at startup.

### Local validation

After building, run the collector regression tests without credentials or network access:

```powershell
docker run --rm --network none `
  --mount "type=bind,source=${PWD}\tools\test_collect.sh,target=/tmp/test_collect.sh,readonly" `
  --entrypoint bash fcli-data-collector:1.0.0 `
  -c 'sed "s/\r$//" /tmp/test_collect.sh | bash'
```

The tests cover default and individual collectors, full-window findings, failure manifests, and rejection of the removed collectors. fcli is mocked; this does not verify live FoD access.

## Run

```powershell
docker run --rm `
  -v "${PWD}/out:/data/out" `
  -e FOD_URL=https://api.ams.fortify.com `
  -e FOD_CLIENT_ID=... -e FOD_CLIENT_SECRET_FILE=/run/secrets/fod_client_secret `
  -v "${PWD}/secrets/fod_client_secret:/run/secrets/fod_client_secret:ro" `
  -e SOURCE_INSTANCE_ID=fod-ams-prod `
  -e WINDOW_DAYS=2 `
  fcli-data-collector:1.0.0
```

The output directory must be writable by UID 10001 (on Linux hosts: `chown 10001 out` or run with `--user $(id -u):$(id -g)`).

On Windows, run the command above from PowerShell with Docker Desktop using Linux containers (WSL2). Bind-mounted folders need no permission changes. Secret files may contain a UTF-8 BOM and CRLF line endings; only the first line is used.

### Credentials

Every value can also be supplied as `<NAME>_FILE` pointing to a mounted secret file. Setting both is an error. Secrets are passed to fcli through environment variables, never on the command line, and are not written to the output.

| Variable | Description |
|---|---|
| `FOD_URL` | FoD API base URL, e.g. `https://api.ams.fortify.com`. |
| `FOD_CLIENT_ID`, `FOD_CLIENT_SECRET` | API key (client credentials). Preferred: assign only the applications to collect to the key. |
| `FOD_TENANT`, `FOD_USER`, `FOD_PAT` | Alternative: user with a personal access token. |
| `FOD_SCOPES` | Requested scopes. Default `view-apps,view-issues` (read-only). |

### Collection settings

| Variable | Default | Description |
|---|---|---|
| `COLLECTORS` | `inventory,findings` | Comma-separated subset to run; only `inventory` and `findings` are supported. |
| `WINDOW_DAYS` | `2` | Incremental window in whole UTC days (0–30); `full` takes a full snapshot. |
| `INVENTORY_MODE` | `full` | `full` snapshot of applications/releases every run, or `window` to apply `WINDOW_DAYS`. |
| `RELEASE_FILTERS` | _(all)_ | Server-side FoD filters expression for releases, e.g. `sdlcStatusType:Production|QA`. |
| `RELEASE_QUERY` | _(none)_ | SpEL query over release records, e.g. `!suspended && rating <= 3`. |
| `APPLICATION_ATTRIBUTES` | _(none)_ | Application attribute selection: `Name=Value1|Value2;Other Name=Value`. |
| `APPLICATION_QUERY` | _(none)_ | SpEL query over application records, e.g. `businessCriticalityType == 'High'`. |
| `CLASSIFIERS` | `all` | Comma-separated classifier ids to apply, `all`, or `none`. |
| `CLASSIFIERS_DIR` | _(none)_ | Mounted directory with custom classifier YAML files (same id overrides a built-in). |
| `CLASSIFIER_MODE` | `tag` | `tag`: export all selected findings and add `classifications`; `filter`: export only findings matching a classifier. |
| `SCAN_TYPE` | `All` | Findings scan type: `Static`, `Dynamic`, `Mobile`, `OpenSource`, `Network`, `Monitoring`, `All`. |
| `SEVERITIES` | `Critical,High` | Findings severities, or `All`. |
| `SOURCE_INSTANCE_ID` | _(empty)_ | Stable tenant identifier written into every document. |
| `OUTPUT_DIR` | `/data/out` | Mounted output directory. |
| `OUTPUT_UMASK` | `027` | File mode mask for output (findings are sensitive; widen only if the consumer needs it). |
| `ACTION_PUBKEY` | _(unset)_ | Path to a mounted public key. When set, actions must be signed with the matching key. |
| `FCLI_LOG_LEVEL` | _(off)_ | e.g. `INFO`/`DEBUG`; writes fcli logs to `logs/` in the run directory (masked on a best-effort basis). |

## Selecting applications and releases

All selection settings are combined (AND) and resolved **once per run** into a release list that the inventory and findings collectors share. If no setting is given, every release visible to the credentials is collected; restricting the API key's application access remains the strongest control.

| Want | Setting |
|---|---|
| Production releases only | `RELEASE_FILTERS=sdlcStatusType:Production` |
| Production and QA, not suspended | `RELEASE_FILTERS=sdlcStatusType:Production|QA` and `RELEASE_QUERY=!suspended` |
| Applications with an attribute value | `APPLICATION_ATTRIBUTES=Business Unit=Payments` |
| AI applications | `APPLICATION_ATTRIBUTES=AI Application Type=LLM Application|AI Agent` |
| High business criticality | `APPLICATION_QUERY=businessCriticalityType == 'High'` |

Queries are SpEL expressions over the records returned by `fcli fod release list` / `fcli fod app list -o json`; test them with those commands and `-q`. The run fails (exit code 2) when the selection matches no releases. The selection used is recorded in every document (`selection`).

## Classifiers

Classifiers label findings with the conditions you care about. Each classifier is a YAML file evaluated by fcli against native FoD issue fields (the same fields `fcli fod issue list -o json` shows), optionally restricted to applications matching an application query.

```yaml
id: my-critical-sqli            # lowercase, unique; a custom file with a built-in id overrides it
version: 1                      # bump when the logic changes; recorded with every finding set
title: Critical SQL injection
scan_types: [Static]            # optional: Static, Dynamic, Mobile, OpenSource, Network, Monitoring
issue_query: >-                 # SpEL over FoD issue fields; use single quotes, no double quotes
  severityString == 'Critical' && category == 'SQL Injection'
application_query: >-           # optional SpEL over the owning application record
  attributes.?[name == 'Business Unit' && value == 'Payments'].size() > 0
```

Built-in classifiers ([classifiers/](classifiers/)):

| Id | Matches |
|---|---|
| `fod-aviator-sast-true-positive` | Static, `fortifyAviator == true`, auditor status Remediation Required, excluding `agentic/` and `prompt-injection/` rules, in applications whose `AI Application Type` is `LLM Application` or `AI Agent`. |
| `fod-aviator-dast-true-positive` | Same for Dynamic findings. |
| `fod-aviator-guidance-available` | `aviatorRemediationGuidanceAvailable == true`, any scan type. |
| `fod-oss-malware` | Open source findings with FoD `malware == true`. |
| `fod-oss-exploited` | Open source findings with FoD `exploited == true`. |

Mount custom classifiers read-only and point `CLASSIFIERS_DIR` at them:

```powershell
docker run --rm -v "${PWD}/out:/data/out" -v "${PWD}/my-classifiers:/config/classifiers:ro" `
  -e CLASSIFIERS_DIR=/config/classifiers -e CLASSIFIERS=fod-oss-malware,my-critical-sqli -e CLASSIFIER_MODE=filter `
  -e RELEASE_FILTERS=sdlcStatusType:Production ... fcli-data-collector:1.0.0
```

Classifier files are validated at startup (unknown keys, invalid ids or scan types, and double quotes in queries are rejected) and their SHA-256 is written to the findings document and the manifest. Classifier queries are executable expressions: only mount files from a trusted source.

Classifier results are FoD evidence, not verdicts: `fortifyAviator` means Aviator audited the issue, not that a fix was applied; `exploited`/`malware` are FoD-native flags, and null means unknown.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All collectors succeeded. |
| 1 | At least one collector failed; the run directory and manifest are still written. |
| 2 | Configuration, integrity or login error; no run directory is published. |

## Cost and limits

- Findings are queried for each release and each day in the window (`releases × (WINDOW_DAYS+1)` list calls), plus one detail call per exported finding. With classifiers, each release that has changed findings is listed once more so the classifier queries can run against it. Use the selection settings and API-key scoping on large tenants.
- All records of a collection are held in memory until written.

## Running actions without the container

```powershell
fcli fod session login --url https://api.ams.fortify.com --client-id ... --client-secret ...
fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore --window-days 2 --scan-type All --file findings.json
fcli fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore --applications-file applications.json --releases-file releases.json
```

Use `--release <id|app:release>` with the findings action for a single release.

`--action-sha256` is a custom option declared by the inventory and findings actions, not a built-in fcli option. The runner supplies it for provenance after verifying the bundled action checksums.

The findings action reads classifiers from `COLLECTOR_CLASSIFIER_<n>_*` environment variables, which the container generates from the YAML files. Outside the container, load them into the current PowerShell session first (needs Python with PyYAML); this also clears stale variables from earlier runs:

```powershell
. .\bin\Set-CollectorEnv.ps1 -Mode filter                      # all built-in classifiers
. .\bin\Set-CollectorEnv.ps1 -Classifiers fod-oss-malware,my-rule -ClassifiersDir .\my-classifiers
fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore --scan-type All --release "MyApp:main" --file findings.json
```

Without these variables the action runs with no classifiers (`--classifier-mode filter` then fails).

## Debugging classifiers against FoD

### Classifiers directly against FoD

Use read-only `fcli fod issue list` queries to inspect current source evidence without exporting, ingesting, or connecting to the SignalBridge database. These examples use native FoD property names, not the normalized finding-store names. Use an existing authenticated session; the commands do not log in/out or update findings. Command options were checked against fcli 3.29.0.

```powershell
$release = "application:release" # Or a native release ID
$fodSession = "default"
$include = "visible,suppressed,fixed"
```

**Aviator-reviewed findings requiring remediation.** `fortifyAviator=true` indicates Aviator audit evidence, not that Aviator applied a fix. The SAST and DAST classifiers also require either supported auditor-status spelling and exclude `agentic/` and `prompt-injection/` rule IDs. Guidance availability is independent and is not required by these classifiers.

```powershell
#$aviatorQuery = "fortifyAviator == true && {'Remediation Required','Required Remediation'}.contains(auditorStatus) && (checkId == null || !(checkId.startsWith('agentic/') || checkId.startsWith('prompt-injection/')))"

# SAST: source predicate for fod-aviator-sast-true-positive
$aviatorQuery = "fortifyAviator == true && {'Remediation Required','Required Remediation'}.contains(auditorStatus)"
fcli fod issue list --rel $release --fod-session $fodSession --include $include --filters-param "scantype:Static" --query $aviatorQuery -o json

# DAST: source predicate for fod-aviator-dast-true-positive
$aviatorQuery = "fortifyAviator == true && {'Remediation Required','Required Remediation'}.contains(auditorStatus)"
fcli fod issue list --rel $release --fod-session $fodSession --include $include --filters-param "scantype:Dynamic" --query $aviatorQuery -o json

# Broader diagnostic: guidance exists, regardless of audit disposition
fcli fod issue list --rel $release --fod-session $fodSession --include $include --query "aviatorRemediationGuidanceAvailable == true" -o json
```

If both Aviator classifiers additionally require the owning application's `AI Application Type` attribute to be exactly `LLM Application` or `AI Agent`. Check that source context separately; issue rows alone cannot establish a full classifier match:

```powershell
$releaseInfo = fcli fod release get $release --fod-session $fodSession -o json | ConvertFrom-Json
fcli fod app get $releaseInfo.applicationId --fod-session $fodSession -o json
```

**Open source malware or exploitation flags.** FoD issue rows use `scantype='Open Source'`; the collector normalizes this to `OpenSource` / `SCA`. These predicates mirror the built-in [fod-oss-malware](classifiers/fod-oss-malware.yaml) and [fod-oss-exploited](classifiers/fod-oss-exploited.yaml) classifiers.

```powershell
# Either risk flag
fcli fod issue list --rel $release --fod-session $fodSession --include $include --query "scantype == 'Open Source' && (malware == true || exploited == true)" -o json

# Malware only
fcli fod issue list --rel $release --fod-session $fodSession --include $include --query "scantype == 'Open Source' && malware == true" -o json

# Exploitation flag only
fcli fod issue list --rel $release --fod-session $fodSession --include $include --query "scantype == 'Open Source' && exploited == true" -o json
```

`exploited=true` reports FoD's native flag, not independently established exploitability, an `Exploitable` auditor disposition, or KEV membership. Missing/null flags are unknown, not false. Likewise, `malware=true` is a source assertion, not an independent malware verdict.

For comparisons with a collection, use the same release, session, severity selection and source context. These debugging queries intentionally include all severities and visible/suppressed/fixed findings. The default collector selects Critical/High; add `&& {'Critical','High'}.contains(severityString)` to an existing query to match that selection. For the Aviator examples, also change the explicit server filter to `scantype:Static+severityString:Critical|High` or `scantype:Dynamic+severityString:Critical|High` so it agrees with the query. Use `--include visible` for a visible-only investigation. Do not use `--fetch` when comparing complete result sets: it caps records, not page size.

Classifier evidence is not an active-Signal verdict: lifecycle, suppression, application context and Signal rules are evaluated separately. Live source changes since collection can also explain differences. `status` (source lifecycle), `developerStatus`, and `auditorStatus` are distinct; neither required remediation nor available Aviator guidance proves a completed, scan-validated fix or identifies who applied it.

JSON exposes the raw matching fields even when the default table omits them. Start without `--embed`; only add `--embed details,recommendations` when investigating explanation/guidance content, as embedding makes extra requests and can hit FoD rate limits. Avoid requesting sensitive HTTP request/response data. Query options are verified locally, but representative live OSS flag results still require tenant validation.