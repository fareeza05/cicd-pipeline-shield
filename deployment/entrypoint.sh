#!/bin/sh
set -e

TARGET="${1:-/data}"

echo "=================================================="
echo "  Shield-Pipe Security Scanner"
echo "  Target : ${TARGET}"
echo "  Report : /app/reports/security_report.json"
echo "=================================================="

# No-op if /app/reports is a host-mounted volume; otherwise ensure
# the in-container directory exists so the reporter can write to it.
mkdir -p /app/reports

# exec replaces this shell so SIGTERM from `docker stop` and the
# scanner's sys.exit() code propagate cleanly to the Jenkins stage.
exec python scanner/main.py "$@"
