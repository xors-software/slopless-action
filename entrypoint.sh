#!/usr/bin/env bash
set -euo pipefail

# Slopless GitHub Action entrypoint
# Zips the repo and sends it to the Slopless hosted API for scanning.
# No local dependencies needed — just bash, curl, jq, zip.

API_URL="${SLOPLESS_API_URL:-https://api.slopless.work}"
LICENSE_KEY="${SLOPLESS_LICENSE_KEY:?Missing SLOPLESS_LICENSE_KEY}"
SCAN_DIR="${GITHUB_WORKSPACE:-.}/${SCAN_PATH:-.}"
AUTO_FIX="${AUTO_FIX:-true}"
CROSS_VALIDATE="${CROSS_VALIDATE:-true}"

REPORT_FILE="${RUNNER_TEMP:-/tmp}/slopless-report.md"
JSON_FILE="${RUNNER_TEMP:-/tmp}/slopless-result.json"
ZIP_FILE="${RUNNER_TEMP:-/tmp}/slopless-upload.zip"

echo "::group::Slopless Security Scan"
echo "API: ${API_URL}"
echo "Scanning: ${SCAN_DIR}"

# ── Zip the repo (exclude heavy/irrelevant dirs) ────────────────────────
echo "Packaging codebase..."
cd "${SCAN_DIR}"
zip -r -q "${ZIP_FILE}" . \
  -x ".git/*" \
  -x "node_modules/*" \
  -x "__pycache__/*" \
  -x ".venv/*" \
  -x "venv/*" \
  -x "dist/*" \
  -x "build/*" \
  -x ".next/*" \
  -x ".nuxt/*" \
  -x "*.pyc" \
  -x ".DS_Store"

ZIP_SIZE=$(du -sh "${ZIP_FILE}" | cut -f1)
echo "Upload size: ${ZIP_SIZE}"

# ── Upload to Slopless API ──────────────────────────────────────────────
echo "Uploading to Slopless API..."
HTTP_CODE=$(curl -s -o "${JSON_FILE}" -w "%{http_code}" \
  -X POST "${API_URL}/v1/proxy/scan/upload" \
  -H "Authorization: Bearer ${LICENSE_KEY}" \
  -F "file=@${ZIP_FILE};type=application/zip" \
  -F "auto_fix=${AUTO_FIX}" \
  -F "cross_validate=${CROSS_VALIDATE}" \
  -F "parallel_candidates=3" \
  -F "run_polish=false" \
  --max-time 600)

echo "::endgroup::"

# ── Handle API response ─────────────────────────────────────────────────
if [[ "${HTTP_CODE}" -eq 401 ]]; then
  echo "::error::Invalid or expired license key"
  echo "total=0" >> "$GITHUB_OUTPUT"
  echo "critical=0" >> "$GITHUB_OUTPUT"
  echo "high=0" >> "$GITHUB_OUTPUT"
  echo "exit_code=1" >> "$GITHUB_OUTPUT"
  exit 1
fi

if [[ "${HTTP_CODE}" -lt 200 || "${HTTP_CODE}" -ge 300 ]]; then
  echo "::error::Slopless API returned HTTP ${HTTP_CODE}"
  if [ -f "${JSON_FILE}" ]; then
    cat "${JSON_FILE}" >&2
  fi
  echo "total=0" >> "$GITHUB_OUTPUT"
  echo "critical=0" >> "$GITHUB_OUTPUT"
  echo "high=0" >> "$GITHUB_OUTPUT"
  echo "exit_code=1" >> "$GITHUB_OUTPUT"
  exit 1
fi

# ── Parse results ────────────────────────────────────────────────────────
SUCCESS=$(jq -r '.success // true' "${JSON_FILE}")
if [[ "${SUCCESS}" == "false" ]]; then
  ERROR=$(jq -r '.error // "Unknown error"' "${JSON_FILE}")
  echo "::error::Scan failed: ${ERROR}"
  echo "total=0" >> "$GITHUB_OUTPUT"
  echo "critical=0" >> "$GITHUB_OUTPUT"
  echo "high=0" >> "$GITHUB_OUTPUT"
  echo "exit_code=1" >> "$GITHUB_OUTPUT"
  exit 1
fi

TOTAL=$(jq '[.vulnerabilities // [] | length] | add // 0' "${JSON_FILE}")
CRITICAL=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "critical" or .severity == "CRITICAL")] | length' "${JSON_FILE}")
HIGH=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "high" or .severity == "HIGH")] | length' "${JSON_FILE}")
MEDIUM=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "medium" or .severity == "MEDIUM")] | length' "${JSON_FILE}")
LOW=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "low" or .severity == "LOW")] | length' "${JSON_FILE}")
WARNING=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "warning" or .severity == "WARNING")] | length' "${JSON_FILE}")
INFO=$(jq '[.vulnerabilities // [] | .[] | select(.severity == "info" or .severity == "INFO")] | length' "${JSON_FILE}")

echo "Found ${TOTAL} findings (${CRITICAL} critical, ${HIGH} high, ${MEDIUM} medium, ${LOW} low, ${WARNING} warning, ${INFO} info)"

# ── Generate markdown report ─────────────────────────────────────────────
{
  echo "# Security Vulnerability Report"
  echo ""
  echo "## Summary"
  echo ""
  echo "| Severity | Count |"
  echo "|----------|-------|"
  echo "| Critical | ${CRITICAL} |"
  echo "| High | ${HIGH} |"
  echo "| Medium | ${MEDIUM} |"
  echo "| Low | ${LOW} |"
  echo "| Warning | ${WARNING} |"
  echo "| Info | ${INFO} |"
  echo "| **Total** | **${TOTAL}** |"
  echo ""

  if [[ "${TOTAL}" -eq 0 ]]; then
    echo "No vulnerabilities found."
  else
    echo "## Vulnerabilities"
    echo ""
    # Extract each vulnerability into markdown
    jq -r '
      .vulnerabilities // [] | to_entries[] |
      "### \(.key + 1). [\(.value.severity // "medium" | ascii_upcase)] \(.value.title // "Untitled")\n" +
      "**Location:** `\(.value.file_path // "unknown"):\(.value.line_number // "?")`\n" +
      (if .value.cwe_id then "**CWE:** \(.value.cwe_id)\n" else "" end) +
      "\n" +
      (if .value.description then "**Description:**\n\(.value.description)\n\n" else "" end) +
      (if .value.code_snippet then "**Vulnerable Code:**\n```\n\(.value.code_snippet)\n```\n\n" else "" end) +
      (if .value.recommendation then "**Recommendation:**\n\(.value.recommendation)\n\n" else "" end) +
      "---\n"
    ' "${JSON_FILE}"
  fi
} > "${REPORT_FILE}"

# ── Set outputs ──────────────────────────────────────────────────────────
echo "report=${REPORT_FILE}" >> "$GITHUB_OUTPUT"
echo "total=${TOTAL}" >> "$GITHUB_OUTPUT"
echo "critical=${CRITICAL}" >> "$GITHUB_OUTPUT"
echo "high=${HIGH}" >> "$GITHUB_OUTPUT"

if [[ "${TOTAL}" -eq 0 ]]; then
  echo "exit_code=0" >> "$GITHUB_OUTPUT"
  echo "::notice::No vulnerabilities found"
else
  echo "exit_code=1" >> "$GITHUB_OUTPUT"
  echo "::warning::Found ${TOTAL} vulnerabilities (${CRITICAL} critical, ${HIGH} high)"
fi

# ── GitHub Actions Job Summary ───────────────────────────────────────────
{
  echo "## Slopless Security Scan Results"
  echo ""
  echo "| Severity | Count |"
  echo "|----------|-------|"
  echo "| Critical | ${CRITICAL} |"
  echo "| High | ${HIGH} |"
  echo "| Medium | ${MEDIUM} |"
  echo "| Low | ${LOW} |"
  echo "| Warning | ${WARNING} |"
  echo "| Info | ${INFO} |"
  echo "| **Total** | **${TOTAL}** |"
  echo ""
  if [[ "${TOTAL}" -gt 0 ]]; then
    echo "<details><summary>Full Report</summary>"
    echo ""
    cat "${REPORT_FILE}"
    echo ""
    echo "</details>"
  fi
} >> "$GITHUB_STEP_SUMMARY"
