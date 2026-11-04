# FoD fcli Actions

These standalone, read-only actions export FoD inventory and findings:

- `fod-export-inventory.fcli` writes application and release collections.
- `fod-export-findings.fcli` writes findings with optional classifier labels.

Run the examples from the repository root in PowerShell. Create the output directory first; the actions do not create parent directories.

## Prerequisites and Login

### Install fcli

Check whether fcli is available:

```powershell
fcli --version
```

If fcli is unavailable and Node.js/npm is installed, use the official Fortify setup package:

```powershell
npx @fortify/setup env init --tools=fcli:auto
npx @fortify/setup env powershell | Invoke-Expression
fcli --version
```

Alternatively, download the Windows package from the [official fcli releases](https://github.com/fortify/fcli/releases), extract it, and add `fcli.exe` to `PATH`. Follow your organization's software-installation and signature-verification requirements.

### Create FoD credentials

In FoD, have an administrator create or assign an API key for the collector. Keep the key's client ID and secret, grant it access to the applications/releases to be exported, and request the read scopes `view-apps` and `view-issues`. Use the FoD API URL for your region, for example `https://api.ams.fortify.com`.

Provide the client secret to the shell through your approved secret store; do not place the secret directly in a command or a checked-in script. In this example, `FOD_CLIENT_SECRET` is assumed to have been populated securely:

```powershell
$env:FCLI_DEFAULT_FOD_CLIENT_SECRET = $env:FOD_CLIENT_SECRET
$env:FOD_URL = 'https://api.ams.fortify.com'
$env:FOD_CLIENT_ID = '<client-id>'

fcli fod session login --url $env:FOD_URL `
  --client-id $env:FOD_CLIENT_ID `
  --scopes view-apps,view-issues
```

The `FCLI_DEFAULT_FOD_CLIENT_SECRET` environment default supplies the secret without putting it on the command line. fcli stores the authenticated session for subsequent FoD commands. When finished, close it with `fcli fod session logout`.

Create an output directory once:

```powershell
New-Item -ItemType Directory -Force .\out | Out-Null
```

### PowerShell argument note

Some Windows fcli launchers pass arguments through `cmd.exe`, which treats `|` as a pipe even when it is quoted in PowerShell. For commands whose argument contains `|`, use PowerShell's stop-parsing token `--%` and put the command on one line. After `--%`, PowerShell does not expand variables or process backtick continuations, so use literal values.

## Inventory

The inventory action always exports applications and releases. Without a scope it can cover everything visible to the FoD credentials. To keep an export narrow, create a scope from FoD release records and pass its fcli variable name with `--scope-var`.

| Input | Use |
|---|---|
| `--applications-file` | Output file for the applications collection. |
| `--releases-file` | Output file for the releases collection. |
| `--release-filters` | FoD release-list filter expression; ignored when `--scope-var` is used. Example: `sdlcStatusType:Production|QA`. |
| `--scope-var` | fcli variable containing FoD release records, created with `fcli fod release list --store`. Limits releases and applications to the scope. |
| `--release-query` | Optional SpEL expression recorded in output metadata only. It does not filter records; use `-q` when creating a scope to apply the expression. |
| `--application-query` | Optional application-selection expression recorded in metadata only. It does not filter records. |
| `--window-days` | Optional integer from `0` through `30`; exports items modified since UTC midnight N days ago. Omit for a full snapshot. |
| `--source-instance` | Optional stable FoD tenant/instance identifier written to output. |
| `--action-sha256` | Optional action hash supplied by a trusted runner for provenance. |

Export inventory for one application's `main` release. The `-q` expression selects the release; the action itself receives only the resulting scope:

```powershell
fcli fod release list --app 'My Application' `
  -q "releaseName == 'main'" --store selected_releases

fcli fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore `
  --scope-var selected_releases `
  --applications-file .\out\applications.json `
  --releases-file .\out\releases.json
```

For a tenant-wide release filter containing `|`, use `--%` as described above:

```powershell
fcli --% fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore --release-filters "sdlcStatusType:Production|QA" --applications-file .\out\applications.json --releases-file .\out\releases.json
```

`--window-days 2` changes the inventory to a modified-since window. In scope mode, the stored release records take precedence over `--release-filters`.

## Findings

By default, findings exports are Static, Critical/High, and cover releases visible to the session. Use `--release`, `--release-filters`, or `--scope-var` to limit the releases.

| Input | Use |
|---|---|
| `--release`, `--rel` | One FoD release ID or `application:release`. Mutually exclusive with `--release-filters` and `--scope-var`. |
| `--release-filters` | FoD release-list filter expression; mutually exclusive with `--release`, and ignored when `--scope-var` is used. |
| `--scope-var` | fcli variable containing FoD release records. Overrides release listing. |
| `--release-query`, `--application-query` | Optional selection expressions recorded in output metadata only; they do not filter findings or resolve scope. |
| `--classifier-mode` | `tag` adds matching classifier IDs while retaining selected findings; `filter` exports only findings matching at least one classifier. Defaults to `tag`. |
| `--scan-type` | `Static`, `Dynamic`, `Mobile`, `OpenSource`, `Network`, `Monitoring`, or `All`. Defaults to `Static`. FoD's native `Open Source` is selected as `OpenSource`. |
| `--severities`, `--severity-string` | Comma-separated `Critical`, `High`, `Medium`, `Low`, `Info`, `Best_Practice`, or `All`. Defaults to `Critical,High`. |
| `--window-days` | Incremental window, integer `0` through `30`; `0` means today in UTC. Mutually exclusive with `--modified-since`. |
| `--modified-since` | One UTC day in `YYYY/MM/DD` format. Mutually exclusive with `--window-days`. |
| `--source-instance` | Optional stable FoD tenant/instance identifier written to output. |
| `--action-sha256` | Optional action hash supplied by a trusted runner for provenance. |
| `--file` | Output file for the findings collection. |

Export one release with the default scan type and severities:

```powershell
fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore `
  --release 'My Application:main' `
  --file .\out\findings.json
```

To include all scan types and severities for that release, add `--scan-type All --severities All`. For incremental results, add either `--window-days 2` or `--modified-since 2026/11/02`.

### Classifiers

The findings action reads classifier definitions from consecutive environment-variable groups: `COLLECTOR_CLASSIFIER_0_*`, `COLLECTOR_CLASSIFIER_1_*`, and so on, with no gaps. Each needs `ID` and `ISSUE_QUERY`. For provenance, also set `VERSION`, `TITLE`, and `SHA256`. If the classifier has an application predicate, set `APPLICATION_QUERY` too. These variables are not loaded from YAML automatically; this section shows manual setup without Python scripts.

Built-in FoD definitions are in [`../classifiers/fod/`](../classifiers/fod/):

| ID | Scan type | Finding predicate | Application predicate |
|---|---|---|---|
| `fod-aviator-sast-true-positive` | Static | Aviator audited true and auditor status requires remediation | High business criticality |
| `fod-aviator-dast-true-positive` | Dynamic | Aviator audited true and auditor status requires remediation | High business criticality |
| `fod-aviator-guidance-available` | Any | Remediation guidance is available | High business criticality |
| `fod-oss-exploited` | OpenSource | FoD `exploited == true` | High business criticality |
| `fod-oss-malware` | OpenSource | FoD `malware == true` | High business criticality |

For example, configure the malware classifier and filter to matching findings:

```powershell
$classifierPath = '.\classifiers\fod\fod-oss-malware.yaml'
$env:COLLECTOR_CLASSIFIER_MODE = 'filter'
$env:COLLECTOR_CLASSIFIER_0_ID = 'fod-oss-malware'
$env:COLLECTOR_CLASSIFIER_0_VERSION = '1'
$env:COLLECTOR_CLASSIFIER_0_TITLE = 'Open source component flagged as malware by FoD'
$env:COLLECTOR_CLASSIFIER_0_SHA256 = (Get-FileHash $classifierPath -Algorithm SHA256).Hash.ToLowerInvariant()
$env:COLLECTOR_CLASSIFIER_0_ISSUE_QUERY = 'malware == true'
$env:COLLECTOR_CLASSIFIER_0_APPLICATION_QUERY = "businessCriticalityType == 'High'"

fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore `
  --classifier-mode filter `
  --release 'My Application:main' `
  --scan-type OpenSource `
  --severities All `
  --file .\out\malware-findings.json
```

Use `tag` instead of `filter` to keep nonmatching findings in the export and attach classifier labels only to matches. Classifier application predicates require FoD application-read access. These labels represent FoD evidence, not an independent verdict or proof a fix was applied.

## Combined Scenarios

### Same release in both exports

Create one scope and reuse it so the inventory and findings exports process the same release. Replace the sample app and release names with values from the tenant:

```powershell
fcli fod release list --app 'My Application' `
  -q "releaseName == 'main'" --store demo_scope

fcli fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore `
  --scope-var demo_scope `
  --applications-file .\out\applications.json `
  --releases-file .\out\releases.json

fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore `
  --scope-var demo_scope `
  --file .\out\findings.json
```

### Production and QA releases

The pipe in the FoD filter requires `--%` in PowerShell. Resolve the scope once and pass it to both actions:

```powershell
fcli --% fod release list --filters-param "sdlcStatusType:Production|QA" --store prod_qa
fcli fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore --scope-var prod_qa --applications-file .\out\applications.json --releases-file .\out\releases.json
fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore --scope-var prod_qa --file .\out\findings.json
```

### Active or suspended releases

To exclude suspended releases, filter them out while creating the scope. To include them, omit `-q`. The scope, not the action's optional `--release-query` metadata input, determines which releases are exported.

```powershell
# Active releases only.
fcli fod release list --app 'My Application' -q "!suspended" --store active_releases

# Include active and suspended releases instead.
fcli fod release list --app 'My Application' --store all_releases
```

Pass the chosen variable to either action using `--scope-var`. Add `--release-query '!suspended'` only when you want the active-only predicate recorded in that export's metadata.

### Incremental collection

Use the same scope for a smaller incremental run; inventory and findings windows are independent options on their respective actions:

```powershell
fcli fod action run actions/fod-export-inventory.fcli --on-unsigned=ignore --scope-var demo_scope --window-days 2 --applications-file .\out\applications.json --releases-file .\out\releases.json
fcli fod action run actions/fod-export-findings.fcli --on-unsigned=ignore --scope-var demo_scope --window-days 2 --file .\out\findings.json
```

Incremental exports are not full snapshots. Release filters, scopes, scan type, severity, and classifier `filter` mode limit coverage; an absent finding is not evidence that it was fixed. `--on-unsigned=ignore` is an fcli action-runner option used in these local examples; `--action-sha256` is an optional action input for trusted runners that verify action integrity.