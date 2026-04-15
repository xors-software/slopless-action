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
  --max-time "${SCAN_TIMEOUT:-1800}")

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

# ── Extract scan digest (engine v0.2+; every scan ships a digest) ───────
# Gracefully omit the digest block if the engine response doesn't carry it,
# so this action stays compatible with older engine deployments.
HAS_DIGEST=$(jq 'if .summary.scan_digest then true else false end' "${JSON_FILE}")
if [[ "${HAS_DIGEST}" == "true" ]]; then
  D_FILES=$(jq -r '.summary.scan_digest.files_scanned // 0' "${JSON_FILE}")
  D_LINES=$(jq -r '.summary.scan_digest.lines_scanned // 0' "${JSON_FILE}")
  D_ENTRY=$(jq -r '.summary.scan_digest.entry_points_identified // 0' "${JSON_FILE}")
  D_SVCS=$(jq -r '.summary.scan_digest.services_identified // 0' "${JSON_FILE}")
  D_SUB=$(jq -r '.summary.scan_digest.candidates_submitted // 0' "${JSON_FILE}")
  D_VER=$(jq -r '.summary.scan_digest.candidates_verified // 0' "${JSON_FILE}")
  D_REJ=$(jq -r '.summary.scan_digest.candidates_rejected // 0' "${JSON_FILE}")
  D_XVAL=$(jq -r '.summary.scan_digest.cross_validation_rejected // 0' "${JSON_FILE}")
  D_CONF=$(jq -r '.summary.scan_digest.confidence_score // 0' "${JSON_FILE}")
  D_REASON=$(jq -r '.summary.scan_digest.confidence_rationale // ""' "${JSON_FILE}")
  D_LANGS=$(jq -r '.summary.scan_digest.languages // {} | to_entries | map("\(.key) (\(.value))") | join(", ")' "${JSON_FILE}")
  D_FRAMEWORKS=$(jq -r '.summary.scan_digest.frameworks // [] | join(", ")' "${JSON_FILE}")
  D_COVERAGE=$(jq -r '.summary.scan_digest.coverage // [] | join(" · ")' "${JSON_FILE}")
  # OWASP grouping table (one row per evaluated OWASP Top 10 2021 bucket).
  # Empty string when the engine is older than v0.3 and doesn't emit the field.
  HAS_OWASP=$(jq 'if .summary.scan_digest.coverage_by_owasp and (.summary.scan_digest.coverage_by_owasp | length > 0) then true else false end' "${JSON_FILE}")
  if [[ "${HAS_OWASP}" == "true" ]]; then
    D_OWASP_ROWS=$(jq -r '
      .summary.scan_digest.coverage_by_owasp
      | to_entries
      | sort_by(.key)
      | map("| \(.value.category) | \(.value.checks_performed) | \(.value.findings) |")
      | join("\n")
    ' "${JSON_FILE}")
  fi

  # Confidence emoji: 5 green, 4 yellow, 3 orange, <=2 red.
  case "${D_CONF}" in
    5) CONF_EMOJI="🟢" ;;
    4) CONF_EMOJI="🟡" ;;
    3) CONF_EMOJI="🟠" ;;
    *) CONF_EMOJI="🔴" ;;
  esac
fi

# ── Generate markdown report ─────────────────────────────────────────────
{
  if [[ "${HAS_DIGEST}" == "true" ]]; then
    echo "# Slopless Security Scan — ${CONF_EMOJI} ${D_CONF}/5 confidence"
    echo ""
    echo "> ${D_REASON}"
    echo ""
    echo "## Scope"
    echo ""
    echo "| Files | LoC | Languages | Frameworks |"
    echo "|-------|-----|-----------|------------|"
    echo "| ${D_FILES} | ${D_LINES} | ${D_LANGS:-—} | ${D_FRAMEWORKS:-—} |"
    echo ""
    echo "## Architecture"
    echo ""
    echo "- **${D_ENTRY}** entry points identified"
    echo "- **${D_SVCS}** service(s)"
    echo ""
    echo "## Scanner activity"
    echo ""
    echo "| Submitted | Verified | Rejected | Cross-val rejected |"
    echo "|:---------:|:--------:|:--------:|:------------------:|"
    echo "| ${D_SUB} | ${D_VER} | ${D_REJ} | ${D_XVAL} |"
    echo ""
    # Prefer the grouped OWASP table when the engine provides it; fall back
    # to the flat pill list for compatibility with older engine deployments.
    if [[ "${HAS_OWASP}" == "true" ]]; then
      echo "## Coverage (OWASP Top 10 2021)"
      echo ""
      echo "| Category | Checks | Findings |"
      echo "|----------|:------:|:--------:|"
      echo "${D_OWASP_ROWS}"
      echo ""
    elif [[ -n "${D_COVERAGE}" ]]; then
      echo "**Vulnerability classes evaluated:** ${D_COVERAGE}"
      echo ""
    fi
    echo "## Findings"
    echo ""
  else
    echo "# Security Vulnerability Report"
    echo ""
    echo "## Summary"
    echo ""
  fi
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
