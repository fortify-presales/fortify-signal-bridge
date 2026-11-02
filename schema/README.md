# fortify.collector data contract

This directory is the contract between the FoD collector container and downstream correlation tools. Every file the collector writes is a JSON document validated by the schemas here (JSON Schema draft 2020-12).

| Version | Status | Contents |
|---|---|---|
| [v1.0](v1.0/) | Frozen | Initial schema. |

Validate output with `python tools/validate_output.py <run-dir>` (needs `pip install jsonschema`).

The current collector emits only applications, releases and findings, plus a run manifest. Scan and event schemas remain available to validate older output; the corresponding collectors and example documents have been removed. Existing collected data is not deleted.

## Versioning rules

TBD

## Output layout

```
<OUTPUT_DIR>/fod/<UTC yyyyMMddTHHmmssZ>-<run_id>/
  manifest.json                 # written last; index of the run
  applications.json             # collection_type=applications
  releases.json                 # collection_type=releases
  findings.json                 # collection_type=findings
```

Runs are written to `.partial-<name>` and renamed when complete. **Only read directories whose name does not start with `.`** and that contain `manifest.json`. A failed collector is listed in the manifest with `status: failed`; its files may be missing.

## Envelope (all collections)

Defined in [v1.0/envelope.schema.json](v1.0/envelope.schema.json). The current payload arrays are named after `collection_type` (`findings`, `applications`, `releases`). The schema also accepts legacy scan and event collections.

| Field | Type | Meaning |
|---|---|---|
| `schema_name` / `schema_version` | string | `fortify.collector` / `1.0`. |
| `collection_type` | enum | Currently emitted: `findings`, `applications`, `releases`. |
| `collection_id` | string | fcli run id of the producing action. Several files may share it. |
| `started_at` / `completed_at` | date-time | Collector wall clock (UTC). |
| `source_platform` | `fod` | |
| `source_instance_id` | string\|null | Runner-supplied stable tenant identifier (`SOURCE_INSTANCE_ID`). Use it to keep tenants apart. |
| `requested_scope` | string | `tenant`, or the release requested with `--release`. |
| `release_filters` | string\|null | FoD filters expression used to pick releases. |
| `selection` | object | `release_filters`, `release_query`, `application_query` used to resolve the release set; all null = everything the credentials can see. |
| `resolved_scope_ids` | string[] | Release ids covered. Empty when the collection is not release-scoped. |
| `window` | object\|null | `null` = full snapshot. Otherwise `days`, inclusive `start` (UTC midnight N days ago), `end`, `granularity` (`day` or `rolling-24h`). |
| `producer` | object | fcli version, `collector_id`, `collector_version`, and `collector_sha256` (hash of the action file). |
| `coverage.coverage_mode` | enum | `incremental` (window), `full-snapshot`, `filtered-snapshot`. |
| `coverage.authoritative_for_lifecycle` | boolean | Only `true` when a missing record really means it no longer exists (unfiltered full inventory). **Never infer remediation or deletion from absence otherwise.** |
| `coverage.fetched_count` | integer | Number of payload records. |
| `coverage.capabilities` / `warnings` | string[] | What the document contains / known coverage limits. |

## Incremental windows

`WINDOW_DAYS=N` selects whole UTC days from `today-N` to today (N=2 → 3 calendar days). Windows of consecutive runs are expected to **overlap**; consumers must upsert by the dedupe keys below. The collector keeps no state.

| Collection | FoD filter used | Dedupe key |
|---|---|---|
| findings | `lastModifiedDate` (one call per day, merged) | `source_instance_id` + `release_id` + `source_finding_id` (latest `completed_at` wins) |
| applications | `modifiedStartDate` (only with `INVENTORY_MODE=window`) | `application_id` |
| releases | `modifiedStartDate` (only with `INVENTORY_MODE=window`) | `release_id` |

## findings

Schema: [v1.0/findings.schema.json](v1.0/findings.schema.json). Additional top-level fields: `classification`, `scan_type`, `severities` (empty = all), `modified_since` (legacy), `scope` (single-release runs only), `profile`.

`classification` describes the classifiers applied in this run:

| Field | Meaning |
|---|---|
| `mode` | `tag`: every selected finding is exported; `filter`: only findings matching at least one classifier are exported. |
| `classifiers[]` | `id`, `version`, `title`, `sha256` of each classifier file. Compare `sha256` to detect logic changes. |
| `matched_count` | Number of exported findings with at least one classification. |

| Field | FoD source | Notes |
|---|---|---|
| `source_finding_id` | `vulnId` | Unique within a release. |
| `instance_id` | `instanceId` | Stable Fortify instance id across scans. |
| `source_url` | derived | FoD browser link. |
| `application_id`, `application_name`, `release_id`, `release_name` | release record | Owning release. |
| `ai_application_type` | application attribute `AI Application Type` | `Non AI`, `LLM Application`, `AI Agent`, or `null` if missing, ambiguous or unsupported. |
| `classifications` | classifier evaluation | Ids of the classifiers in `classification.classifiers` that match. Empty = none matched. |
| `scan_id` | `scanId` | Scan that last reported the issue. |
| `rule_id` | `checkId` | |
| `finding_domain` | `scantype` | `SAST`, `DAST`, `MAST`, `SCA`, `NETWORK`, `MONITORING`, `UNKNOWN`. |
| `source_scan_type` | `scantype` | `Open Source` normalized to `OpenSource`. |
| `analyzer_name`, `impact`, `probability`, `confidence` | issue details | |
| `category`, `severity` | `category`, `severityString` | |
| `source_status` | `status` | FoD lifecycle, e.g. New, Existing, Reopen, Fix Validated. |
| `developer_status`, `auditor_status` | same | Audit state; independent of `source_status`. |
| `suppressed` | `isSuppressed` | |
| `fortify_aviator` | `fortifyAviator` | Aviator audited the issue. Does not mean a fix was applied. |
| `aviator_remediation_guidance_available` | `aviatorRemediationGuidanceAvailable` | |
| `exploited`, `malware` | `exploited`, `malware` | FoD-native flags (OSS). `null` = unknown, not false. Not a KEV or independent verdict. |
| `introduced_date`, `closed_date`, `last_modified_date` | same | As returned by FoD (time zone not always present). |
| `sca_provider`, `component_*`, `advisory_ids` | — | Reserved; always null/empty in 1.0. |
| `summary`, `explanation`, `recommendation` | details / recommendations | Converted to plain text. |
| `file_path`, `line` | `primaryLocationFull`, `lineNumber` | `line` is null when FoD reports 0. |
| `traces[]` | trace entries | `file_path`, `line`, `message` for each step. Static findings only. |

HTTP request/response data from DAST findings is never exported.

## applications / releases

Schemas: [v1.0/applications.schema.json](v1.0/applications.schema.json), [v1.0/releases.schema.json](v1.0/releases.schema.json). Applications are never narrowed by `release_filters` (only API-key access applies). Releases include SDLC status, star rating, pass/fail, current scan ids and dates, issue counts and attributes.

## manifest.json

Schema: [v1.0/manifest.schema.json](v1.0/manifest.schema.json). Contains `run_id`, overall `status`, non-secret `settings`, and for each collector: `status`, `exit_code` and `outputs[]` (`file`, `bytes`, `sha256`, `collection_type`, `record_count`). Verify file hashes before ingesting.

## Examples

[../examples/run/](../examples/run/) contains a complete synthetic run that validates against these schemas.
