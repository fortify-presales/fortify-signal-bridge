# Fortify SignalBridge MVP Implementation Plan

## 1. Purpose

This document defines how to extend the existing fcli- and Docker-enabled Fortify collector repository into a lightweight **Fortify SignalBridge MVP** that:

1. collects findings from Fortify on Demand (FoD);
2. validates and normalises the collection;
3. evaluates configurable signal rules;
4. creates versioned `fortify.signal` events;
5. sends those events to one or more output sinks;
6. exits after one finite execution cycle.

The MVP deliberately avoids a database, message broker, internal scheduler, REST server, and permanently running daemon.

The deployment platform remains responsible for scheduling. Suitable schedulers include Kubernetes CronJob, Azure Container Apps Jobs, Jenkins, GitHub Actions, cron, and Windows Task Scheduler.

---

## 2. Architectural decision

### 2.1 Recommended model

Implement the collector and processor as logically separate modules inside the same one-shot container:

```text
External scheduler
        |
        v
Fortify SignalBridge container
        |
        +-- 1. Collect from FoD using fcli
        |
        +-- 2. Validate collection contract
        |
        +-- 3. Evaluate signal rules
        |
        +-- 4. Build fortify.signal events
        |
        +-- 5. Write local output artifacts
        |
        +-- 6. Send events through configured sinks
        |
        +-- 7. Write final run manifest
        |
        v
       Exit
```

### 2.2 Key boundary

The modules have different responsibilities even though they execute in the same container:

| Module | Responsibility |
|---|---|
| Collector | Retrieve authoritative FoD source data and preserve native evidence and provenance. |
| Processor | Convert source observations and classifier evidence into target-neutral security signals. |
| Sink | Serialise and deliver signals to a destination such as JSON, standard output, or CrowdStrike HEC. |
| Scheduler | Decide when the one-shot container runs. This remains outside the application. |

### 2.3 MVP delivery semantics

The initial implementation provides **at-least-once delivery**.

The same unchanged finding may be emitted again after a retry or overlapping collection window. Every signal must therefore have a deterministic `event_id` so the destination can correlate or deduplicate repeated observations.

Without persistent lifecycle state, the MVP must not infer that an absent finding is resolved.

```text
Finding observed  -> emit an observation signal
Finding absent    -> emit nothing
```

Do not implement this behaviour in the MVP:

```text
Finding absent -> resolved
```

---

## 3. Proposed repository structure

Adapt names to the repository's existing language and conventions, but preserve these logical boundaries:

```text
.
|-- actions/
|   |-- fod-export-inventory.fcli
|   `-- fod-export-findings.fcli
|-- classifiers/
|   `-- *.yaml
|-- config/
|   |-- signal-rules.yaml
|   `-- sinks.example.yaml
|-- docker/
|   `-- entrypoint.sh
|-- processors/
|   |-- collection_reader.py
|   |-- signal_engine.py
|   |-- signal_mapper.py
|   `-- validation.py
|-- rules/
|   |-- aviator-confirmed.yaml
|   |-- exploited-open-source.yaml
|   |-- reachable-open-source.yaml
|   `-- correlated-sast-dast.yaml
|-- schemas/
|   |-- collection/
|   |-- fortify-signal-v1.schema.json
|   `-- run-manifest-v1.schema.json
|-- sinks/
|   |-- base.py
|   |-- stdout_sink.py
|   |-- json_sink.py
|   `-- crowdstrike_hec_sink.py
|-- tests/
|   |-- fixtures/
|   |-- test_event_ids.py
|   |-- test_rules.py
|   |-- test_signal_mapping.py
|   `-- test_sinks.py
|-- examples/
|   |-- signals.ndjson
|   `-- run-manifest.json
|-- README.md
|-- Dockerfile
`-- pyproject.toml
```

If the existing repository is not Python-based, use equivalent packages/modules while retaining the same separation of concerns.

---

## 4. Runtime workflow

### 4.1 Entrypoint flow

The container entrypoint should execute the following stages in order:

```text
validate configuration
        |
        v
authenticate to FoD
        |
        v
collect applications/releases/findings
        |
        v
validate collection documents
        |
        v
process findings and classifications
        |
        v
evaluate signal rules
        |
        v
write signals.ndjson
        |
        v
deliver signals to configured sinks
        |
        v
write final manifest
        |
        v
logout and exit
```

A failure in configuration, collection validation, signal mapping, or required sink delivery should result in a non-zero exit code.

### 4.2 Suggested commands

Expose the orchestration through explicit commands:

```text
signalbridge collect
signalbridge process
signalbridge deliver
signalbridge run
signalbridge validate
```

For normal scheduled execution:

```text
signalbridge run
```

`run` performs collect, process, and deliver in a single execution.

The individual commands remain useful for development, testing, troubleshooting, and demonstrations.

### 4.3 Run modes

Support a small set of explicit run modes:

```text
RUN_MODE=incremental
RUN_MODE=full
RUN_MODE=targeted
```

Recommended semantics:

- `incremental`: collect recently changed findings using an overlapping time window;
- `full`: collect all relevant findings in the selected scope;
- `targeted`: collect a specified application, release, or set of release IDs.

Do not label a run as authoritative for lifecycle merely because `RUN_MODE=full`. Record actual coverage separately in the output manifest.

---

## 5. Configuration

### 5.1 Required source configuration

```text
FORTIFY_PLATFORM=fod
FOD_API_URL=https://api.example.invalid
FOD_AUTH_URL=https://ams.example.invalid/oauth/token
FOD_CLIENT_ID_FILE=/run/secrets/fod_client_id
FOD_CLIENT_SECRET_FILE=/run/secrets/fod_client_secret
SOURCE_INSTANCE_ID=customer-fod-prod
```

`SOURCE_INSTANCE_ID` must be mandatory outside local development. It must be stable and must not be a casually editable display name.

### 5.2 Scope configuration

```text
RUN_MODE=incremental
APPLICATION_NAMES=ApplicationA,ApplicationB
RELEASE_IDS=12345,67890
WINDOW_DAYS=2
```

Use either application names or release IDs according to current repository behaviour. The process should fail fast if mutually exclusive or incomplete scope settings are supplied.

### 5.3 Processor configuration

```text
SIGNAL_RULES_PATH=/app/rules
SIGNAL_SCHEMA_VERSION=1.0
DETAIL_LEVEL=summary
FAIL_ON_INVALID_FINDING=false
FAIL_ON_INVALID_SIGNAL=true
```

Recommended detail levels:

- `summary`: IDs, application/release, category, severity, states, dates, classifications, and deep link;
- `standard`: summary plus source location, component/advisory fields, and concise description;
- `full`: standard plus full explanation, recommendation, and trace data.

Use `summary` for the initial CISO Command Center integration.

### 5.4 Sink configuration

```text
SINKS=json,crowdstrike
JSON_OUTPUT_PATH=/data/out/signals.ndjson
CROWDSTRIKE_HEC_URL_FILE=/run/secrets/crowdstrike_hec_url
CROWDSTRIKE_HEC_TOKEN_FILE=/run/secrets/crowdstrike_hec_token
CROWDSTRIKE_TIMEOUT_SECONDS=30
CROWDSTRIKE_MAX_RETRIES=4
CROWDSTRIKE_BATCH_SIZE=100
```

Do not place client secrets, tokens, or credentials directly in environment variables in controlled deployments. Prefer Docker/Kubernetes secret files or the deployment platform's managed secret facility.

---

## 6. Signal contract

### 6.1 Design goals

The `fortify.signal` contract must be:

- versioned;
- target-neutral;
- compact enough for SIEM ingestion;
- traceable to the source finding;
- explicit about evidence and rule provenance;
- deterministic for repeated observations;
- free of CrowdStrike-specific business logic.

### 6.2 Example signal

```json
{
  "schema_name": "fortify.signal",
  "schema_version": "1.0",
  "event_id": "sha256:4fb2...",
  "event_type": "fortify.signal.observed",
  "observed_at": "2026-11-02T15:30:00Z",
  "source": {
    "platform": "fod",
    "instance_id": "customer-fod-prod",
    "application_id": 101,
    "release_id": 202879,
    "finding_id": "dcc9e589-example",
    "deep_link": "https://example.invalid/finding"
  },
  "application": {
    "name": "IWA-NodeJS",
    "release": "main"
  },
  "signal": {
    "type": "aviator-confirmed-sast",
    "severity": "critical",
    "confidence": "high",
    "title": "Confirmed critical SAST finding"
  },
  "finding": {
    "domain": "SAST",
    "category": "Cross-Site Scripting: Reflected",
    "cwe": "CWE-79",
    "source_status": "Open",
    "auditor_status": "Remediation Required",
    "suppressed": false,
    "last_modified": "2026-11-02T15:20:00Z"
  },
  "evidence": {
    "classifications": [
      {
        "id": "fod-aviator-sast-true-positive",
        "version": "1",
        "matched": true
      }
    ]
  },
  "provenance": {
    "collection_id": "13fb7c17-example",
    "collector_version": "1.2",
    "processor_version": "0.1.0",
    "signal_rule_id": "aviator-confirmed-critical",
    "signal_rule_version": "1"
  }
}
```

### 6.3 Event identity

Generate `event_id` from stable source and rule inputs. Use canonical encoding and a documented field order.

Recommended input:

```text
source platform
+ source instance ID
+ release ID
+ source finding ID
+ source last-modified timestamp
+ signal rule ID
+ signal rule version
+ signal schema version
```

Conceptual derivation:

```text
event_id = SHA-256(canonical_event_identity_input)
```

The event identity function must be covered by unit tests. The same logical observation must produce the same event ID on every platform and execution.

Do not include `observed_at`, collection ID, random values, or output destination in the event identity, because those would make retries produce different IDs.

---

## 7. Classification and signal rules

### 7.1 Preserve the distinction

A classifier describes source evidence:

```text
"The finding matches the FoD Aviator classification criteria."
```

A signal rule makes a destination-facing decision:

```text
"Emit a high-confidence application-risk signal for this critical, unsuppressed finding."
```

Do not combine these concepts in one expression.

### 7.2 Example rule format

```yaml
id: aviator-confirmed-critical
version: "1"
description: Emit confirmed critical SAST findings identified by Aviator.
enabled: true
when:
  all:
    - classification: fod-aviator-sast-true-positive
      equals: true
    - field: finding.severity
      in: [Critical]
    - field: finding.suppressed
      equals: false
emit:
  type: aviator-confirmed-sast
  confidence: high
  severity_from: finding.severity
  title: Confirmed critical SAST finding
```

### 7.3 Initial rule set

Start with a small, explainable rule set:

1. `aviator-confirmed-critical`
2. `reachable-open-source-critical`
3. `known-exploited-open-source`
4. `correlated-sast-dast-high`
5. `agentic-or-llm-application-risk`

Only implement a rule when the source fields needed for it are present and their semantics are understood. A missing or unknown value must remain distinct from `false`.

### 7.4 Rule provenance

Every emitted signal must record:

- rule ID;
- rule version;
- classifier IDs and versions used;
- processor version;
- collection ID;
- source record identifiers.

---

## 8. Sink interface

### 8.1 Contract

All sinks should implement the same logical interface:

```text
open(run_context)
send(batch_of_signals)
flush()
close()
```

A sink must not change signal meaning. Destination-specific field wrapping should happen only in the sink adapter.

### 8.2 JSON sink

The JSON sink should write `signals.ndjson`, one complete signal per line.

Advantages:

- stream processing;
- simple inspection with command-line tools;
- lower memory use;
- straightforward retry and replay;
- simple upload to other systems.

### 8.3 Standard-output sink

The standard-output sink is useful for local tests and container-native pipelines. Ensure secrets never appear in the output.

### 8.4 CrowdStrike HEC sink

The CrowdStrike sink should:

- send HTTPS requests to the configured endpoint;
- authenticate using a mounted secret;
- use bounded batches;
- set an explicit connection and request timeout;
- retry transient HTTP failures with exponential backoff and jitter;
- treat authentication and schema failures as non-retryable;
- never log the token;
- include the deterministic event ID;
- report attempted, accepted, retried, and failed event counts.

The sink must not mark the run successful if required delivery has failed after all retries.

### 8.5 Retry policy

Suggested initial policy:

```text
maximum attempts: 4
base delay:       1 second
maximum delay:    30 seconds
jitter:           enabled
retry:            network errors, HTTP 408, 429, and 5xx
no retry:         HTTP 400, 401, 403, and other permanent request errors
```

The exact HTTP success and error handling must be validated against the chosen destination endpoint before production use.

---

## 9. File-based execution and publication

### 9.1 Run directory

Use one directory per execution:

```text
/data/out/.staging/<collection-id>/
    applications.json
    releases.json
    findings.json
    signals.ndjson
    manifest.json
```

After successful validation and required sink delivery, publish atomically:

```text
/data/out/complete/<collection-id>/
```

For a failed run:

```text
/data/out/failed/<collection-id>/
```

This makes troubleshooting possible without treating the output folder as a database.

### 9.2 Manifest

The final manifest should contain:

```json
{
  "schema_name": "fortify.signalbridge.run",
  "schema_version": "1.0",
  "collection_id": "13fb7c17-example",
  "run_mode": "incremental",
  "started_at": "2026-11-02T15:25:00Z",
  "completed_at": "2026-11-02T15:30:00Z",
  "status": "complete",
  "coverage": {
    "retrieval_complete": true,
    "snapshot_consistent": false,
    "authoritative_for_lifecycle": false
  },
  "counts": {
    "findings_collected": 130,
    "findings_valid": 130,
    "signals_emitted": 12,
    "signals_delivered": 12,
    "signals_failed": 0
  },
  "documents": [
    {
      "name": "signals.ndjson",
      "record_count": 12,
      "sha256": "example"
    }
  ],
  "sinks": [
    {
      "id": "crowdstrike",
      "required": true,
      "status": "complete",
      "delivered": 12,
      "failed": 0
    }
  ]
}
```

Write the final manifest last.

---

## 10. Optional checkpoint file

A database is not required for the MVP. An optional checkpoint file can still improve collection efficiency:

```text
/data/state/checkpoint.json
```

Example:

```json
{
  "schema_version": "1.0",
  "source_instance_id": "customer-fod-prod",
  "last_successful_run": "2026-11-02T15:30:00Z",
  "last_collection_id": "13fb7c17-example",
  "last_window_end": "2026-11-02T15:29:00Z"
}
```

Rules:

- update the checkpoint only after successful required sink delivery;
- write to a temporary file and rename atomically;
- apply an overlap when deriving the next collection window;
- allow stateless operation when no checkpoint volume is mounted;
- do not use this file to infer finding closure or signal resolution.

Suggested configuration:

```text
CHECKPOINT_ENABLED=false
CHECKPOINT_PATH=/data/state/checkpoint.json
CHECKPOINT_OVERLAP_MINUTES=60
```

Keep checkpoint support disabled by default for the first demonstration if it complicates deployment.

---

## 11. Error handling and exit codes

Use predictable exit codes suitable for external schedulers:

| Code | Meaning |
|---:|---|
| 0 | Collection, processing, validation, and required sink delivery succeeded. |
| 1 | Run completed with permitted partial source results; no lifecycle inference is allowed. |
| 2 | Configuration, authentication, collection, schema, or processing failure produced no publishable result. |
| 3 | Temporary upstream or destination failure; scheduler may retry. |
| 4 | Output publication or required sink delivery failed. |

If the repository already has a stable `0/1/2` contract, preserve it initially and express additional failure categories in the manifest rather than breaking existing automation.

---

## 12. Security requirements

Retain the repository's existing non-root and secret-file approach and add the following where practical:

- run as a non-root UID;
- use a read-only root filesystem;
- drop all Linux capabilities;
- enable `no-new-privileges`;
- use `/tmp` as a bounded `tmpfs`;
- mount output and optional state directories explicitly;
- restrict egress to the FoD and destination endpoints;
- never write credentials to logs or output manifests;
- verify bundled fcli action hashes before execution;
- pin the base image by digest for controlled builds;
- generate an SPDX or CycloneDX SBOM;
- scan the image and dependencies in CI;
- sign release images if moving beyond a PoC;
- use read-only FoD service credentials with the minimum required application scope.

Example hardened Docker options:

```text
--read-only
--cap-drop ALL
--security-opt no-new-privileges
--tmpfs /tmp:rw,noexec,nosuid,size=64m
```

---

## 13. Observability

### 13.1 Structured logs

Log JSON to standard output. Include:

- timestamp;
- log level;
- stage;
- collection ID;
- source instance ID;
- application/release ID where safe;
- counts and duration;
- error category;
- retry attempt.

Do not log secrets, access tokens, complete source traces, or entire vulnerability explanations by default.

### 13.2 Run metrics

Record at least:

```text
applications resolved
releases resolved
findings listed
findings exported
findings rejected
rules evaluated
signals produced
signals delivered
signals failed
API retries
rate-limit responses
run duration
```

Write these values to both the structured log and final manifest.

---

## 14. Testing strategy

### 14.1 Unit tests

Implement tests for:

- canonical event-ID generation;
- null/unknown versus false handling;
- every initial signal rule;
- severity and state mapping;
- sink batching;
- retry classification;
- manifest counts;
- credential redaction.

### 14.2 Contract tests

Use the repository's current sample `findings.json` as an immutable fixture. Validate that:

- it conforms to the collection schema;
- expected findings produce expected signals;
- non-matching findings produce no signal;
- signal output conforms to `fortify-signal-v1.schema.json`;
- repeated processing produces identical event IDs.

### 14.3 Sink tests

Use a local mock HTTP server to test:

- successful batch delivery;
- HTTP 429 retry;
- HTTP 500 retry;
- HTTP 400 permanent failure;
- timeout behaviour;
- partial batch handling;
- token redaction.

Do not require real CrowdStrike credentials in normal CI tests.

### 14.4 End-to-end test

Provide a deterministic test mode:

```text
signalbridge run \
  --input tests/fixtures/findings.json \
  --sink json \
  --output /tmp/signals.ndjson
```

This bypasses FoD authentication and allows the processing pipeline to be tested locally and in CI.

---

## 15. Docker implementation

### 15.1 Image responsibilities

The Docker image should contain:

- the approved fcli version;
- validated fcli actions;
- the processor runtime;
- signal schemas and rules;
- sink adapters;
- the one-shot entrypoint.

It should not contain:

- source or destination credentials;
- an internal cron daemon;
- a database;
- a message broker;
- customer-specific configuration baked into the image.

### 15.2 Example execution

```text
docker run --rm \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v ./out:/data/out \
  -v ./secrets:/run/secrets:ro \
  -e SOURCE_INSTANCE_ID=customer-fod-prod \
  -e RUN_MODE=incremental \
  -e SINKS=json,crowdstrike \
  fortify-signalbridge:0.1.0 run
```

Adapt the command to the repository's current image name and entrypoint.

---

## 16. CI/CD changes

Add pipeline stages for:

```text
lint
  -> unit tests
  -> schema validation
  -> contract tests
  -> build image
  -> image vulnerability scan
  -> generate SBOM
  -> smoke test one-shot execution
  -> publish versioned image
```

Recommended release metadata:

- semantic image version;
- Git commit SHA;
- fcli version;
- collector action checksum;
- classifier bundle checksum;
- signal-rule bundle checksum;
- schema versions.

Record these values in the run manifest.

---

## 17. Implementation phases

### Phase 1: Local signal generation

Deliverables:

- `fortify.signal` JSON Schema;
- signal mapper;
- deterministic event IDs;
- initial rule engine;
- JSON/NDJSON sink;
- fixture-based tests;
- `signalbridge process` command.

Acceptance criteria:

- existing `findings.json` can be processed without FoD access;
- output validates against the signal schema;
- rerunning the same input produces the same event IDs;
- no database or checkpoint is required.

### Phase 2: Combined one-shot pipeline

Deliverables:

- `signalbridge run` orchestration;
- collection, processing, and JSON delivery in one container run;
- final run manifest;
- atomic complete/failed publication;
- structured logs and exit codes.

Acceptance criteria:

- one Docker command retrieves FoD findings and creates `signals.ndjson`;
- a collection or schema failure prevents successful publication;
- output and logs contain no credentials.

### Phase 3: CrowdStrike delivery

Deliverables:

- CrowdStrike HEC sink;
- batching;
- timeout and retry handling;
- delivery metrics;
- mock-server integration tests.

Acceptance criteria:

- valid signals are delivered successfully;
- retryable failures are retried with bounded backoff;
- permanent failures produce a non-zero exit code;
- a scheduler retry produces the same event IDs.

### Phase 4: Optional checkpoint

Deliverables:

- atomic checkpoint file;
- configurable overlap window;
- watermark-based incremental collection;
- stateless fallback.

Acceptance criteria:

- checkpoint updates only after complete required delivery;
- deleting the checkpoint does not prevent execution;
- checkpoint state is never used to infer resolution.

### Deferred capabilities

Do not include these in the initial solution:

- authoritative opened/resolved/reopened lifecycle events;
- database-backed state;
- transactional outbox;
- exactly-once delivery;
- source-to-target status reconciliation;
- REST management API;
- web interface;
- internal scheduler;
- horizontal worker scaling;
- multi-tenant orchestration.

---

## 18. Definition of done for the MVP

The MVP is complete when:

- the existing fcli collector still runs independently;
- `signalbridge run` performs collection, processing, and delivery in one finite execution;
- all emitted events conform to a versioned `fortify.signal` schema;
- every event has a deterministic event ID;
- the rule engine is configurable and separate from source classifiers;
- JSON and CrowdStrike sinks share the same target-neutral signal model;
- failed required delivery produces a non-zero exit code;
- scheduled retries are safe under at-least-once semantics;
- absence of a finding never creates a resolution event;
- no database, broker, daemon, or embedded scheduler is required;
- the image runs non-root and does not expose credentials;
- tests cover event identity, key rules, validation, retries, and redaction;
- the README documents configuration, security, execution, limitations, and examples.

---

## 19. Recommended immediate backlog

1. Add `schemas/fortify-signal-v1.schema.json`.
2. Add a canonical event-ID utility and unit tests.
3. Implement `processors/collection_reader` against the existing findings export.
4. Implement a minimal YAML-based signal-rule evaluator.
5. Add two initial rules using fields already present in the current findings contract.
6. Add the NDJSON sink.
7. Add `signalbridge process --input ... --output ...`.
8. Add fixture-based contract tests using the existing sample findings.
9. Add `signalbridge run` to connect the collector and processor.
10. Add the final manifest and atomic complete/failed run directories.
11. Implement the CrowdStrike HEC adapter behind a sink interface.
12. Add mock-server delivery tests and hardened Docker runtime documentation.

---

## 20. Final recommendation

Treat the existing repository as the foundation of **Fortify SignalBridge**, but keep the first implementation deliberately compact:

```text
fcli collector
    -> target-neutral signal processor
    -> deterministic signal events
    -> JSON and CrowdStrike sinks
    -> exit
```

This gives the initial implementationa practical one-shot delivery path without introducing a database prematurely. It also preserves a clean upgrade route to durable lifecycle state, reconciliation, an outbox, and additional destination adapters when operational requirements justify them.
