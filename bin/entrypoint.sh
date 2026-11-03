#!/usr/bin/env bash
# Dispatch a one-shot collector run or a SignalBridge command.
set -euo pipefail
COLLECTOR_HOME="${COLLECTOR_HOME:-/opt/collector}"
if [[ $# -eq 0 ]]; then
  exec "${COLLECTOR_HOME}/bin/collect.sh"
fi
case "$1" in
  collect)
    shift
    exec "${COLLECTOR_HOME}/bin/collect.sh" "$@"
    ;;
  process|deliver|run|validate)
    export PYTHONPATH="${COLLECTOR_HOME}/pydeps:${COLLECTOR_HOME}${PYTHONPATH:+:$PYTHONPATH}"
    exec python3 -m signalbridge "$@"
    ;;
  *)
    echo "Unknown command '$1'. Use collect, process, deliver, run, or validate." >&2
    exit 2
    ;;
esac
