"""signalbridge process | deliver | run | validate | collect."""

import argparse
import json
import os
import subprocess
import sys

from signalbridge.checkpoint import derive_window_days, load_checkpoint, write_checkpoint
from signalbridge.engine import process_collection, utc_now
from signalbridge.log import JsonLog
from signalbridge.publish import build_manifest, publish_run, sha256_file, stage_directory, write_json
from signalbridge.reader import load_findings
from signalbridge.redact import redact, register_secret
from signalbridge.rules import RuleError, load_rules
from signalbridge.sinks import SinkError
from signalbridge.sinks.arcsight import ArcSightCefSink
from signalbridge.sinks.json_sink import JsonSink
from signalbridge.sinks.stdout_sink import StdoutSink
from signalbridge.sinks.crowdstrike import CrowdStrikeHecSink
from signalbridge.validate import SchemaFailure, validate_collector, validate_manifest, validate_signal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_CONFIG = 2
EXIT_TEMPORARY = 3
EXIT_DELIVERY = 4


class ConfigError(Exception):
    pass


def read_secret(name):
    value = os.environ.get(name, "")
    file_name = name + "_FILE"
    file_path = os.environ.get(file_name, "")
    if value and file_path:
        raise ConfigError(f"Set either {name} or {file_name}, not both")
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as handle:
                value = handle.readline().replace("\r", "").lstrip("\ufeff").strip("\n")
        except OSError as exc:
            raise ConfigError(f"{file_name} is not readable") from exc
    if value:
        register_secret(value)
    return value


def _bool_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.lower() in ("1", "true", "yes")


def _int_env(name, default):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def rules_directory(explicit):
    if explicit:
        return explicit
    env = os.environ.get("SIGNAL_RULES_PATH")
    if env:
        return env
    local = os.path.join(ROOT, "rules")
    if os.path.isdir(local):
        return local
    return os.path.join(os.environ.get("COLLECTOR_HOME", "/opt/collector"), "rules")


def classifiers_directory():
    env = os.environ.get("CLASSIFIERS_DIR_BUILTIN")
    if env:
        return env
    local = os.path.join(ROOT, "classifiers")
    if os.path.isdir(local):
        return local
    return os.path.join(os.environ.get("COLLECTOR_HOME", "/opt/collector"), "classifiers")


def detail_level():
    level = os.environ.get("DETAIL_LEVEL", "summary")
    if level not in ("summary", "standard", "full"):
        raise ConfigError("DETAIL_LEVEL must be summary, standard, or full")
    return level


def check_platform():
    platform = os.environ.get("FORTIFY_PLATFORM", "fod")
    if platform not in ("fod", "ssc"):
        raise ConfigError("FORTIFY_PLATFORM must be fod or ssc")
    if platform == "fod" and (os.environ.get("SSC_URL") or os.environ.get("SSC_URL_FILE")):
        raise ConfigError("SSC_URL is not valid when FORTIFY_PLATFORM=fod")
    if platform == "ssc" and (os.environ.get("FOD_URL") or os.environ.get("FOD_URL_FILE")):
        raise ConfigError("FOD_URL is not valid when FORTIFY_PLATFORM=ssc")
    return platform


def require_instance(document):
    instance = os.environ.get("SOURCE_INSTANCE_ID", "")
    if not instance:
        raise ConfigError("SOURCE_INSTANCE_ID is required")
    doc_instance = document.get("source_instance_id")
    if not doc_instance:
        raise ConfigError("Collection is missing source_instance_id")
    if doc_instance != instance:
        raise ConfigError("SOURCE_INSTANCE_ID does not match the collection")


def output_dir():
    return os.environ.get("OUTPUT_DIR", "/data/out")


def collect_script():
    home = os.environ.get("COLLECTOR_HOME")
    if home:
        return os.path.join(home, "bin", "collect.sh")
    return os.path.join(ROOT, "bin", "collect.sh")


def checkpoint_path(platform=None):
    explicit = os.environ.get("CHECKPOINT_PATH")
    if explicit:
        return explicit
    platform = platform or os.environ.get("FORTIFY_PLATFORM", "fod")
    return os.path.join("/data/state", platform, "checkpoint.json")


def apply_checkpoint(log):
    if not _bool_env("CHECKPOINT_ENABLED", False):
        return
    if os.environ.get("RUN_MODE", "incremental") != "incremental":
        return
    path = checkpoint_path()
    checkpoint = load_checkpoint(path)
    if not checkpoint:
        log.info("checkpoint", "No checkpoint file; using WINDOW_DAYS")
        return
    if checkpoint.get("source_instance_id") != os.environ.get("SOURCE_INSTANCE_ID"):
        log.info("checkpoint", "Checkpoint instance does not match; ignoring")
        return
    days = derive_window_days(
        checkpoint.get("last_window_end"),
        overlap_minutes=_int_env("CHECKPOINT_OVERLAP_MINUTES", 60),
    )
    os.environ["WINDOW_DAYS"] = str(days)
    log.info("checkpoint", "Derived collection window", window_days=days)


def save_checkpoint(document, completed_at):
    if not _bool_env("CHECKPOINT_ENABLED", False):
        return
    path = checkpoint_path(document.get("source_platform"))
    window = document.get("window") or {}
    window_end = window.get("end") or completed_at
    write_checkpoint(path, document.get("source_instance_id"), document.get("collection_id"), completed_at, window_end)


def build_sinks(names, artifact_path, level):
    sinks = []
    json_path = os.environ.get("JSON_OUTPUT_PATH") or artifact_path
    if "json" in names or artifact_path:
        sink = JsonSink(json_path if "json" in names else artifact_path)
        sink.required = "json" in names or True
        sink.sink_id = "json"
        sinks.append(sink)
        if "json" in names and json_path != artifact_path:
            extra = JsonSink(artifact_path)
            extra.sink_id = "json-artifact"
            extra.required = True
            sinks.append(extra)
    for name in names:
        if name == "json":
            continue
        if name == "stdout":
            sinks.append(StdoutSink())
        elif name == "crowdstrike":
            url = read_secret("CROWDSTRIKE_HEC_URL")
            token = read_secret("CROWDSTRIKE_HEC_TOKEN")
            if not url or not token:
                raise ConfigError("CrowdStrike sink requires CROWDSTRIKE_HEC_URL and CROWDSTRIKE_HEC_TOKEN secret files or values")
            sinks.append(CrowdStrikeHecSink(
                url, token,
                timeout=_int_env("CROWDSTRIKE_TIMEOUT_SECONDS", 30),
                max_retries=_int_env("CROWDSTRIKE_MAX_RETRIES", 4),
                batch_size=_int_env("CROWDSTRIKE_BATCH_SIZE", 100),
            ))
        elif name == "arcsight":
            host = os.environ.get("ARCSIGHT_HOST", "")
            if not host:
                raise ConfigError("ARCSIGHT_HOST is required when the arcsight sink is enabled")
            port = _int_env("ARCSIGHT_PORT", 514)
            protocol = os.environ.get("ARCSIGHT_PROTOCOL", "tcp")
            syslog_format = os.environ.get("ARCSIGHT_SYSLOG_FORMAT", "rfc5424")
            if protocol not in ("tcp", "udp") or syslog_format not in ("rfc5424", "bsd"):
                raise ConfigError("Invalid ArcSight protocol or syslog format")
            tls = _bool_env("ARCSIGHT_TLS", False)
            ca_file = os.environ.get("ARCSIGHT_CA_FILE") or None
            cert = os.environ.get("ARCSIGHT_CLIENT_CERT_FILE") or None
            key = os.environ.get("ARCSIGHT_CLIENT_KEY_FILE") or None
            if tls and ca_file and not os.path.isfile(ca_file):
                raise ConfigError("ARCSIGHT_CA_FILE is not readable")
            if cert and not os.path.isfile(cert):
                raise ConfigError("ARCSIGHT_CLIENT_CERT_FILE is not readable")
            if key and not os.path.isfile(key):
                raise ConfigError("ARCSIGHT_CLIENT_KEY_FILE is not readable")
            sinks.append(ArcSightCefSink(
                host, port, protocol=protocol, syslog_format=syslog_format,
                timeout=_int_env("ARCSIGHT_TIMEOUT_SECONDS", 30),
                max_retries=_int_env("ARCSIGHT_MAX_RETRIES", 4),
                batch_size=_int_env("ARCSIGHT_BATCH_SIZE", 100),
                tls=tls, ca_file=ca_file, client_cert=cert, client_key=key,
                detail_level=level,
            ))
        else:
            raise ConfigError(f"Unknown sink {name}")
    return sinks


def sink_names(override):
    raw = override or os.environ.get("SINKS", "json")
    names = [item.strip() for item in raw.split(",") if item.strip()]
    if not names:
        raise ConfigError("SINKS is empty")
    return names


def deliver(signals, sinks, log):
    category = None
    for sink in sinks:
        sink.open({})
        try:
            sink.send(signals)
            sink.flush()
        except SinkError as exc:
            sink.status = "failed"
            sink.error_category = exc.category
            if sink.failed == 0:
                sink.failed = len(signals) - sink.delivered
            category = exc.category
            log.error("deliver", redact(str(exc)), sink=sink.sink_id, error_category=exc.category)
            break
        finally:
            try:
                sink.close()
            except SinkError as exc:
                if category is None:
                    category = exc.category
                    sink.status = "failed"
                    sink.error_category = exc.category
                    log.error("deliver", redact(str(exc)), sink=sink.sink_id, error_category=exc.category)
    delivered = min((sink.delivered for sink in sinks if sink.required), default=0)
    failed = max((sink.failed for sink in sinks), default=0)
    return delivered, failed, category


def write_ndjson(path, signals):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for signal in signals:
            handle.write(json.dumps(signal, separators=(",", ":"), ensure_ascii=False) + "\n")


def run_process(path, rules, level, observed_at=None):
    document = load_findings(path)
    require_instance(document)
    cleaned, signals, counts = process_collection(
        document, rules, level,
        fail_on_invalid_finding=_bool_env("FAIL_ON_INVALID_FINDING", False),
        fail_on_invalid_signal=_bool_env("FAIL_ON_INVALID_SIGNAL", True),
        observed_at=observed_at,
        classifiers_dir=classifiers_directory(),
    )
    return cleaned, signals, counts


def publish_signals(document, signals, counts, sinks, rules, started_at, run_mode, success, log):
    collection_id = document.get("collection_id") or "unknown"
    platform = document.get("source_platform")
    staging = stage_directory(output_dir(), collection_id, platform)
    artifact = os.path.join(staging, "signals.ndjson")
    write_ndjson(artifact, signals)
    digest = sha256_file(artifact) if signals or os.path.isfile(artifact) else sha256_file(artifact)
    status = "complete" if success and counts["findings_rejected"] == 0 else ("partial" if success else "failed")
    manifest = build_manifest(
        document, counts, [sink.result() for sink in sinks], started_at, status, run_mode, rules, digest, len(signals),
    )
    write_json(os.path.join(staging, "manifest.json"), manifest)
    try:
        destination = publish_run(output_dir(), collection_id, artifact, manifest, success, platform)
    except (OSError, SchemaFailure) as exc:
        log.error("publish", redact(str(exc)), error_category="permanent")
        return EXIT_DELIVERY, manifest
    log.info("publish", "Published signal run", path=destination, status=status, signals=len(signals))
    return EXIT_OK, manifest


def command_process(args, log):
    rules = load_rules(rules_directory(args.rules))
    level = args.detail or detail_level()
    _cleaned, signals, counts = run_process(args.input, rules, level)
    write_ndjson(args.output, signals)
    log.info("process", "Wrote signals", signals=len(signals), findings=counts["findings_valid"], output=args.output)
    return EXIT_OK


def command_deliver(args, log):
    signals = []
    with open(args.input, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                signal = json.loads(line)
                validate_signal(signal)
                signals.append(signal)
    sinks = build_sinks(sink_names(args.sink), args.input, detail_level())
    # Avoid rewriting the input file when the json sink points at it.
    sinks = [sink for sink in sinks if not isinstance(sink, JsonSink) or sink.path != args.input]
    if not sinks:
        log.info("deliver", "No additional sinks")
        return EXIT_OK
    _delivered, _failed, category = deliver(signals, sinks, log)
    if category == "temporary":
        return EXIT_TEMPORARY
    if category == "permanent":
        return EXIT_DELIVERY
    return EXIT_OK


def command_run(args, log):
    started = utc_now()
    platform = check_platform()
    if not args.input:
        if not os.environ.get("RUN_MODE"):
            if os.environ.get("WINDOW_DAYS") == "full":
                os.environ["RUN_MODE"] = "full"
            elif os.environ.get("RELEASE_IDS"):
                os.environ["RUN_MODE"] = "targeted"
            else:
                os.environ["RUN_MODE"] = "incremental"
        apply_checkpoint(log)
        if not os.environ.get("SOURCE_INSTANCE_ID"):
            raise ConfigError("SOURCE_INSTANCE_ID is required")
        code = subprocess.call([collect_script()])
        if code == 2:
            return EXIT_CONFIG
        if code not in (0, 1):
            return EXIT_CONFIG
        last_run = os.path.join(output_dir(), platform, ".last-run")
        if not os.path.isfile(last_run):
            raise ConfigError("Collector did not record .last-run")
        with open(last_run, encoding="utf-8") as handle:
            run_dir = handle.read().strip()
        findings = os.path.join(run_dir, "findings.json")
        if not os.path.isfile(findings):
            return EXIT_CONFIG
        partial = code == 1
    else:
        findings = args.input
        partial = False
    rules = load_rules(rules_directory(getattr(args, "rules", None)))
    level = detail_level()
    document, signals, counts = run_process(findings, rules, level)
    names = sink_names(getattr(args, "sink", None))
    collection_id = document.get("collection_id") or "local"
    if args.output:
        artifact = args.output
        write_ndjson(artifact, signals)
        sinks = build_sinks(names, artifact, level)
        sinks = [sink for sink in sinks if not (isinstance(sink, JsonSink) and sink.path == artifact)]
        delivered, failed, category = deliver(signals, sinks, log) if sinks else (len(signals), 0, None)
        counts["signals_delivered"] = delivered if sinks else len(signals)
        counts["signals_failed"] = failed
        if category == "temporary":
            return EXIT_TEMPORARY
        if category == "permanent":
            return EXIT_DELIVERY
        manifest = build_manifest(
            document, counts, [sink.result() for sink in sinks], started,
            "partial" if partial else "complete", os.environ.get("RUN_MODE"), rules,
            sha256_file(artifact), len(signals),
        )
        write_json(os.path.splitext(artifact)[0] + ".manifest.json", manifest)
        if category is None and not partial:
            save_checkpoint(document, manifest["completed_at"])
        log.info("run", "Finished file run", signals=len(signals), output=artifact)
        return EXIT_PARTIAL if partial else EXIT_OK
    staging = stage_directory(output_dir(), collection_id, document.get("source_platform"))
    artifact = os.path.join(staging, "signals.ndjson")
    sinks = build_sinks(names, artifact, level)
    delivered, failed, category = deliver(signals, sinks, log)
    counts["signals_delivered"] = delivered
    counts["signals_failed"] = failed
    success = category is None
    code, manifest = publish_signals(
        document, signals, counts, sinks, rules, started, os.environ.get("RUN_MODE"), success, log,
    )
    if code != EXIT_OK:
        return code
    if not success:
        return EXIT_TEMPORARY if category == "temporary" else EXIT_DELIVERY
    save_checkpoint(document, manifest["completed_at"])
    return EXIT_PARTIAL if partial else EXIT_OK


def command_validate(args, log):
    rules = load_rules(rules_directory(args.rules))
    log.info("validate", "Rules accepted", rules=len(rules))
    if not args.input:
        return EXIT_OK
    with open(args.input, encoding="utf-8") as handle:
        raw = handle.read()
    if args.input.endswith(".ndjson"):
        for line in raw.splitlines():
            if line.strip():
                validate_signal(json.loads(line))
        return EXIT_OK
    document = json.loads(raw)
    name = document.get("schema_name")
    if name == "fortify.signal":
        validate_signal(document)
    elif name == "fortify.signalbridge.run":
        validate_manifest(document)
    else:
        validate_collector(document)
    return EXIT_OK


def command_collect(_args, _log):
    return subprocess.call([collect_script()])


def main(argv=None):
    parser = argparse.ArgumentParser(prog="signalbridge")
    sub = parser.add_subparsers(dest="command", required=True)
    process = sub.add_parser("process")
    process.add_argument("--input", required=True)
    process.add_argument("--output", required=True)
    process.add_argument("--rules")
    process.add_argument("--detail")
    deliver_cmd = sub.add_parser("deliver")
    deliver_cmd.add_argument("--input", required=True)
    deliver_cmd.add_argument("--sink")
    run = sub.add_parser("run")
    run.add_argument("--input")
    run.add_argument("--output")
    run.add_argument("--sink")
    run.add_argument("--rules")
    validate = sub.add_parser("validate")
    validate.add_argument("--input")
    validate.add_argument("--rules")
    sub.add_parser("collect")
    args = parser.parse_args(argv)
    log = JsonLog()
    try:
        if args.command == "process":
            return command_process(args, log)
        if args.command == "deliver":
            return command_deliver(args, log)
        if args.command == "run":
            return command_run(args, log)
        if args.command == "validate":
            return command_validate(args, log)
        if args.command == "collect":
            return command_collect(args, log)
    except (ConfigError, RuleError, SchemaFailure, OSError, json.JSONDecodeError) as exc:
        log.error(args.command, redact(str(exc)), error_category="config")
        return EXIT_CONFIG
    return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
