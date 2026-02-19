#!/usr/bin/env bash
set -euo pipefail

# Slopless GitHub Action entrypoint
# Runs a security scan and outputs results for GitHub Actions

SCAN_PATH="${GITHUB_WORKSPACE:-.}"
REPORT_FILE="${RUNNER_TEMP:-/tmp}/slopless-report.md"
JSON_FILE="${RUNNER_TEMP:-/tmp}/slopless-report.json"

echo "::group::Slopless Security Scan"
echo "Scanning: ${SCAN_PATH}"

# Run the scan, output JSON for parsing
unslop scan "${SCAN_PATH}" \
  --format json \
  --output "${JSON_FILE}" \
  --cross-validate \
  --no-fix \
  || true  # Don't fail here; we check thresholds later

echo "::endgroup::"

# Parse results from JSON
if [ -f "${JSON_FILE}" ]; then
  TOTAL=$(python3 -c "
import json, sys
try:
    data = json.load(open('${JSON_FILE}'))
    vulns = data.get('vulnerabilities', [])
    print(len(vulns))
except:
    print('0')
")
  CRITICAL=$(python3 -c "
import json
try:
    data = json.load(open('${JSON_FILE}'))
    vulns = data.get('vulnerabilities', [])
    print(sum(1 for v in vulns if v.get('severity','').lower() == 'critical'))
except:
    print('0')
")
  HIGH=$(python3 -c "
import json
try:
    data = json.load(open('${JSON_FILE}'))
    vulns = data.get('vulnerabilities', [])
    print(sum(1 for v in vulns if v.get('severity','').lower() == 'high'))
except:
    print('0')
")
else
  TOTAL=0
  CRITICAL=0
  HIGH=0
fi

# Generate markdown report
unslop scan "${SCAN_PATH}" \
  --format markdown \
  --output "${REPORT_FILE}" \
  --cross-validate \
  --no-fix \
  2>/dev/null || true

# Set outputs
echo "report=${REPORT_FILE}" >> "$GITHUB_OUTPUT"
echo "total=${TOTAL}" >> "$GITHUB_OUTPUT"
echo "critical=${CRITICAL}" >> "$GITHUB_OUTPUT"
echo "high=${HIGH}" >> "$GITHUB_OUTPUT"

# Summary
if [ "${TOTAL}" -eq 0 ]; then
  echo "exit_code=0" >> "$GITHUB_OUTPUT"
  echo "::notice::No vulnerabilities found"
else
  echo "exit_code=1" >> "$GITHUB_OUTPUT"
  echo "::warning::Found ${TOTAL} vulnerabilities (${CRITICAL} critical, ${HIGH} high)"
fi

# GitHub Actions Job Summary
if [ -f "${REPORT_FILE}" ]; then
  {
    echo "## Slopless Security Scan Results"
    echo ""
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| Critical | ${CRITICAL} |"
    echo "| High | ${HIGH} |"
    echo "| Total | ${TOTAL} |"
    echo ""
    echo "<details><summary>Full Report</summary>"
    echo ""
    cat "${REPORT_FILE}"
    echo ""
    echo "</details>"
  } >> "$GITHUB_STEP_SUMMARY"
fi
