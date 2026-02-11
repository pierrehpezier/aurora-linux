#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="/opt/aurora-linux"
CRON_FILE="/etc/cron.d/aurora-maintenance"
SCHEDULE="17 3 * * *"
SERVICE_NAME="aurora"
ENABLE_BINARY_UPGRADE=0

usage() {
	cat <<'EOF'
Usage: scripts/install-maintenance-cron.sh [options]

Install Aurora maintenance cron jobs:
  1) update signatures
  2) optionally upgrade aurora binary
  3) restart aurora service

Options:
  --install-root <path>      Install root (default: /opt/aurora-linux)
  --cron-file <path>         Cron file path (default: /etc/cron.d/aurora-maintenance)
  --schedule "<cron expr>"   Cron schedule for maintenance (default: "17 3 * * *")
  --service <name>           Systemd service name (default: aurora)
  --enable-binary-upgrade    Also run aurora-util upgrade-aurora in cron job
  -h, --help                 Show help

Examples:
  sudo scripts/install-maintenance-cron.sh
  sudo scripts/install-maintenance-cron.sh --schedule "0 */6 * * *"
  sudo scripts/install-maintenance-cron.sh --enable-binary-upgrade
EOF
}

log() { printf '[maintenance-cron] %s\n' "$*"; }
warn() { printf '[maintenance-cron][warn] %s\n' "$*" >&2; }
die() { printf '[maintenance-cron][error] %s\n' "$*" >&2; exit 1; }

require_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		die "run as root (sudo)"
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--install-root)
			INSTALL_ROOT="${2:-}"
			shift 2
			;;
		--cron-file)
			CRON_FILE="${2:-}"
			shift 2
			;;
		--schedule)
			SCHEDULE="${2:-}"
			shift 2
			;;
		--service)
			SERVICE_NAME="${2:-}"
			shift 2
			;;
		--enable-binary-upgrade)
			ENABLE_BINARY_UPGRADE=1
			shift
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			die "unknown option: $1"
			;;
		esac
	done
}

detect_os_family() {
	if [[ ! -f /etc/os-release ]]; then
		die "cannot detect distro: /etc/os-release not found"
	fi
	# shellcheck source=/etc/os-release
	. /etc/os-release

	local tags="${ID:-} ${ID_LIKE:-}"
	if [[ "${tags}" == *"debian"* || "${tags}" == *"ubuntu"* ]]; then
		echo "debian"
		return
	fi
	if [[ "${tags}" == *"rhel"* || "${tags}" == *"fedora"* || "${tags}" == *"centos"* || "${tags}" == *"rocky"* || "${tags}" == *"alma"* ]]; then
		echo "redhat"
		return
	fi
	if [[ "${tags}" == *"arch"* ]]; then
		echo "arch"
		return
	fi

	die "unsupported distro family: ID=${ID:-unknown} ID_LIKE=${ID_LIKE:-unknown}"
}

enable_cron_service() {
	local os_family="$1"
	local cron_service=""

	case "${os_family}" in
	debian)
		cron_service="cron"
		;;
	redhat | arch)
		cron_service="crond"
		;;
	*)
		die "unsupported os family ${os_family}"
		;;
	esac

	if ! systemctl list-unit-files "${cron_service}.service" >/dev/null 2>&1; then
		warn "cron service ${cron_service}.service not found; install cron package first"
		return
	fi

	systemctl enable --now "${cron_service}.service"
	log "enabled cron service ${cron_service}.service"
}

install_maintenance_script() {
	local maint_script="${INSTALL_ROOT}/bin/aurora-maintenance.sh"
	mkdir -p "${INSTALL_ROOT}/bin" "/var/log/aurora-linux"

	cat >"${maint_script}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT}"
SERVICE_NAME="${SERVICE_NAME}"
RULES_DIR="\${AURORA_MAINT_RULES_DIR:-\${INSTALL_ROOT}/sigma-rules/rules/linux}"
LOCKFILE="\${AURORA_MAINT_LOCKFILE:-/var/lock/aurora-maintenance.lock}"
LOGFILE="\${AURORA_MAINT_LOGFILE:-/var/log/aurora-linux/maintenance.log}"
UPGRADE_BINARY="\${AURORA_MAINT_UPGRADE_BINARY:-$ENABLE_BINARY_UPGRADE}"

mkdir -p "\$(dirname "\${LOGFILE}")" "\$(dirname "\${LOCKFILE}")"
exec >>"\${LOGFILE}" 2>&1
echo "===== \$(date -u +'%Y-%m-%dT%H:%M:%SZ') maintenance start ====="

if command -v flock >/dev/null 2>&1; then
	exec 9>"\${LOCKFILE}"
	if ! flock -n 9; then
		echo "another maintenance run is active; skipping"
		exit 0
	fi
fi

"\${INSTALL_ROOT}/aurora-util" update-signatures --rules-dir "\${RULES_DIR}"

if [[ "\${UPGRADE_BINARY}" == "1" ]]; then
	"\${INSTALL_ROOT}/aurora-util" upgrade-aurora --install-path "\${INSTALL_ROOT}/aurora"
fi

systemctl restart "\${SERVICE_NAME}.service"
systemctl is-active --quiet "\${SERVICE_NAME}.service"
echo "maintenance complete"
EOF

	chmod 0755 "${maint_script}"
	log "installed ${maint_script}"
}

install_cron_entry() {
	local maint_script="${INSTALL_ROOT}/bin/aurora-maintenance.sh"
	mkdir -p "$(dirname "${CRON_FILE}")"
	cat >"${CRON_FILE}" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Aurora maintenance cron (managed by install-maintenance-cron.sh)
# m h dom mon dow user command
${SCHEDULE} root ${maint_script}
EOF
	chmod 0644 "${CRON_FILE}"
	log "installed cron file ${CRON_FILE}"
}

validate_inputs() {
	[[ -x "${INSTALL_ROOT}/aurora-util" ]] || die "${INSTALL_ROOT}/aurora-util is required (run install-service.sh first)"

	local fields
	fields="$(awk '{print NF}' <<<"${SCHEDULE}")"
	if [[ "${fields}" -lt 5 ]]; then
		die "--schedule must contain at least 5 cron fields"
	fi
}

main() {
	parse_args "$@"
	require_root
	validate_inputs

	local os_family
	os_family="$(detect_os_family)"
	log "detected distro family: ${os_family}"
	enable_cron_service "${os_family}"
	install_maintenance_script
	install_cron_entry

	log "cron maintenance installed"
	log "schedule: ${SCHEDULE}"
	log "test run: ${INSTALL_ROOT}/bin/aurora-maintenance.sh"
}

main "$@"
