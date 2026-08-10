#!/usr/bin/env bash
set -euo pipefail

base_dir="${HOME}/.claude-shield"
env_file="${base_dir}/claude-code-privacy.env"

usage() {
  printf '%s\n' 'Usage:'
  printf '%s\n' '  remediate_posix_network.sh            # preview only'
  printf '%s\n' '  remediate_posix_network.sh --apply    # write the environment file'
  printf '%s\n' '  remediate_posix_network.sh --restore BACKUP'
}

case "${1:-}" in
  "")
    printf '%s\n' 'Plan only: create a local file containing the documented Claude Code privacy opt-outs.'
    printf '%s\n' "Target: ${env_file}"
    printf '%s\n' 'No shell profile, network adapter, DNS, route, cache, or device identifier will be changed.'
    ;;
  --apply)
    mkdir -p "${base_dir}/backups"
    chmod 700 "${base_dir}" "${base_dir}/backups"
    backup_base="${base_dir}/backups/claude-code-privacy.$(date -u +%Y%m%d-%H%M%S).$$"
    if [ -f "${env_file}" ]; then
      backup="${backup_base}.env"
      cp "${env_file}" "${backup}"
    else
      backup="${backup_base}.absent"
      : > "${backup}"
    fi
    chmod 600 "${backup}"
    temp_file="$(mktemp "${base_dir}/.privacy-env.XXXXXX")"
    trap 'rm -f "${temp_file}"' EXIT
    printf '%s\n' \
      'export DISABLE_TELEMETRY=1' \
      'export DISABLE_ERROR_REPORTING=1' \
      'export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1' > "${temp_file}"
    chmod 600 "${temp_file}"
    mv "${temp_file}" "${env_file}"
    trap - EXIT
    printf 'Created %s\n' "${env_file}"
    printf 'To apply in the current shell, run: source %q\n' "${env_file}"
    printf 'Rollback: %q --restore %q\n' "$0" "${backup}"
    ;;
  --restore)
    backup="${2:-}"
    [ -f "${backup}" ] || { printf 'Backup not found: %s\n' "${backup}" >&2; exit 2; }
    backup_parent="$(cd "$(dirname "${backup}")" && pwd -P)"
    expected_parent="$(cd "${base_dir}/backups" && pwd -P)"
    [ "${backup_parent}" = "${expected_parent}" ] || { printf '%s\n' "Restore file must be inside ${base_dir}/backups" >&2; exit 2; }
    if [ -f "${env_file}" ] && ! cmp -s "${env_file}" <(printf '%s\n' \
      'export DISABLE_TELEMETRY=1' \
      'export DISABLE_ERROR_REPORTING=1' \
      'export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1'); then
      printf '%s\n' "Refusing to overwrite a modified ${env_file}" >&2
      exit 2
    fi
    if [[ "${backup}" == *.absent ]]; then
      rm -f -- "${env_file}"
      printf 'Removed managed file %s\n' "${env_file}"
    else
      cp "${backup}" "${env_file}"
      chmod 600 "${env_file}"
      printf 'Restored %s from %s\n' "${env_file}" "${backup}"
    fi
    ;;
  *) usage >&2; exit 2 ;;
esac
