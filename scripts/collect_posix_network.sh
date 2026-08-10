#!/usr/bin/env bash
set -euo pipefail

# Limited, read-only POSIX collector. It intentionally emits no host, kernel,
# or environment-variable values.
bool_present() { [ -n "${!1+x}" ] && printf true || printf false; }
bool_active() { [ "${!1-}" = "1" ] && printf true || printf false; }
content_active() { [[ "${!1-}" =~ ^(1|file:.+)$ ]] && printf true || printf false; }
privacy_rows() {
  local active
  if [ "${2:-}" = content ]; then active="$(content_active "$1")"; else active="$(bool_active "$1")"; fi
  printf '[{"Scope":"Process","Present":%s,"Active":%s}]' "$(bool_present "$1")" "${active}"
}

privacy_control() {
  local active
  if [ "${3:-}" = content ]; then active="$(content_active "$1")"; else active="$(bool_active "$1")"; fi
  printf '"%sVars":%s,"%sActive":%s' "$2" "$(privacy_rows "$1" "${3:-}")" "$2" "${active}"
}

if [ "${1:-}" = "--self-test" ]; then
  CLAUDE_SHIELD_SELFTEST_ENV=not-one
  [ "$(bool_present CLAUDE_SHIELD_SELFTEST_ENV)" = true ] || exit 1
  [ "$(bool_active CLAUDE_SHIELD_SELFTEST_ENV)" = false ] || exit 1
  CLAUDE_SHIELD_SELFTEST_ENV=1
  [ "$(bool_active CLAUDE_SHIELD_SELFTEST_ENV)" = true ] || exit 1
  CLAUDE_SHIELD_SELFTEST_ENV=file:/private/trace
  [ "$(content_active CLAUDE_SHIELD_SELFTEST_ENV)" = true ] || exit 1
  case "$(privacy_rows CLAUDE_SHIELD_SELFTEST_ENV content)" in *private*|*trace*|*'"Value"'*) exit 1;; esac
  printf '%s\n' 'Self-test passed.'
  exit 0
fi

COLLECTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat <<EOF
{
  "SchemaVersion": 7,
  "CollectedAt": "${COLLECTED_AT}",
  "System": {
    "Platform": "POSIX",
    "ProxyEnvironmentVariables": [
      { "Name": "HTTP_PROXY", "Present": $(bool_present HTTP_PROXY) },
      { "Name": "HTTPS_PROXY", "Present": $(bool_present HTTPS_PROXY) },
      { "Name": "ALL_PROXY", "Present": $(bool_present ALL_PROXY) },
      { "Name": "NO_PROXY", "Present": $(bool_present NO_PROXY) }
    ]
  },
  "ClaudeCode": {
    $(privacy_control DISABLE_TELEMETRY DisableTelemetry),
    $(privacy_control DISABLE_ERROR_REPORTING DisableErrorReporting),
    $(privacy_control CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC DisableNonessentialTraffic),
    $(privacy_control CLAUDE_CODE_SKIP_PROMPT_HISTORY SkipPromptHistory),
    $(privacy_control CLAUDE_CODE_SUBPROCESS_ENV_SCRUB SubprocessEnvScrub),
    $(privacy_control OTEL_LOG_USER_PROMPTS OtelLogUserPrompts),
    $(privacy_control OTEL_LOG_TOOL_CONTENT OtelLogToolContent),
    $(privacy_control OTEL_LOG_TOOL_DETAILS OtelLogToolDetails),
    $(privacy_control OTEL_LOG_RAW_API_BODIES OtelLogRawApiBodies content)
  }
}
EOF
