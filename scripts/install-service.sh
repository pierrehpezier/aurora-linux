#!/usr/bin/env bash
set -euo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ROOT="$(cd -- "${SELF_DIR}/.." && pwd)"

INSTALL_ROOT="/opt/aurora-linux"
AURORA_BINARY="${SOURCE_ROOT}/aurora"
AURORA_UTIL_BINARY="${SOURCE_ROOT}/aurora-util"
SERVICE_SOURCE="${SOURCE_ROOT}/deploy/aurora.service"
ENV_SOURCE="${SOURCE_ROOT}/deploy/aurora.env"
ENV_TEMPLATE_SOURCE="${SOURCE_ROOT}/deploy/templates/aurora.env.example"
RSYSLOG_TEMPLATE_SOURCE="${SOURCE_ROOT}/deploy/templates/rsyslog-aurora.conf.example"
CRON_TEMPLATE_SOURCE="${SOURCE_ROOT}/deploy/templates/aurora-maintenance.cron.example"
FILENAME_IOC_SOURCE="${SOURCE_ROOT}/resources/iocs/filename-iocs.txt"
C2_IOC_SOURCE="${SOURCE_ROOT}/resources/iocs/c2-iocs.txt"
RULES_SOURCE_DIR=""
SKIP_SIGNATURE_UPDATE=0
FORCE_ENV=0
SKIP_DEPS=0
ENABLE_SERVICE=1
START_SERVICE=1

usage() {
	cat <<'EOF'
Usage: scripts/install-service.sh [options]

Install Aurora as a systemd service on Linux (Ubuntu/Debian, RHEL/Fedora, Arch).

Options:
  --install-root <path>       Install root (default: /opt/aurora-linux)
  --aurora-binary <path>      Path to aurora binary (default: <script-root>/../aurora)
  --aurora-util-binary <path> Path to aurora-util binary (default: <script-root>/../aurora-util)
  --rules-source <path>       Local Sigma rules source to copy (rules/linux or parent)
  --skip-signature-update     Do not run aurora-util update-signatures after install
  --force-env                 Overwrite existing /opt/aurora-linux/config/aurora.env
  --skip-deps                 Skip distro dependency installation
  --disable-service           Do not enable service at boot
  --no-start                  Do not start/restart service after install
  -h, --help                  Show help

Examples:
  sudo scripts/install-service.sh
  sudo scripts/install-service.sh --rules-source /tmp/sigma/rules/linux
  sudo scripts/install-service.sh --skip-signature-update --force-env
EOF
}

log() { printf '[install-service] %s\n' "$*"; }
warn() { printf '[install-service][warn] %s\n' "$*" >&2; }
die() { printf '[install-service][error] %s\n' "$*" >&2; exit 1; }

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
		--aurora-binary)
			AURORA_BINARY="${2:-}"
			shift 2
			;;
		--aurora-util-binary)
			AURORA_UTIL_BINARY="${2:-}"
			shift 2
			;;
		--rules-source)
			RULES_SOURCE_DIR="${2:-}"
			shift 2
			;;
		--skip-signature-update)
			SKIP_SIGNATURE_UPDATE=1
			shift
			;;
		--force-env)
			FORCE_ENV=1
			shift
			;;
		--skip-deps)
			SKIP_DEPS=1
			shift
			;;
		--disable-service)
			ENABLE_SERVICE=0
			shift
			;;
		--no-start)
			START_SERVICE=0
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

install_deps() {
	local os_family="$1"

	if [[ "${SKIP_DEPS}" -eq 1 ]]; then
		log "dependency installation skipped (--skip-deps)"
		return
	fi

	case "${os_family}" in
	debian)
		log "installing dependencies via apt"
		apt-get update
		apt-get install -y ca-certificates curl tar systemd cron
		;;
	redhat)
		if command -v dnf >/dev/null 2>&1; then
			log "installing dependencies via dnf"
			dnf install -y ca-certificates curl tar systemd cronie
		elif command -v yum >/dev/null 2>&1; then
			log "installing dependencies via yum"
			yum install -y ca-certificates curl tar systemd cronie
		else
			die "neither dnf nor yum found"
		fi
		;;
	arch)
		log "installing dependencies via pacman"
		pacman -Sy --noconfirm ca-certificates curl tar systemd cronie
		;;
	*)
		die "unsupported os family ${os_family}"
		;;
	esac
}

install_files() {
	[[ -f "${AURORA_BINARY}" ]] || die "aurora binary not found at ${AURORA_BINARY}"
	[[ -f "${SERVICE_SOURCE}" ]] || die "service template not found at ${SERVICE_SOURCE}"
	[[ -f "${ENV_SOURCE}" ]] || die "env template not found at ${ENV_SOURCE}"

	mkdir -p \
		"${INSTALL_ROOT}/config" \
		"${INSTALL_ROOT}/deploy/templates" \
		"${INSTALL_ROOT}/scripts" \
		"${INSTALL_ROOT}/resources/iocs" \
		"${INSTALL_ROOT}/sigma-rules/rules" \
		"${INSTALL_ROOT}/bin" \
		"/var/log/aurora-linux"

	install -m 0755 "${AURORA_BINARY}" "${INSTALL_ROOT}/aurora"

	if [[ -f "${AURORA_UTIL_BINARY}" ]]; then
		install -m 0755 "${AURORA_UTIL_BINARY}" "${INSTALL_ROOT}/aurora-util"
	else
		warn "aurora-util not found at ${AURORA_UTIL_BINARY}; update features will be unavailable"
	fi

	install -m 0644 "${SERVICE_SOURCE}" "${INSTALL_ROOT}/deploy/aurora.service"

	if [[ -f "${ENV_TEMPLATE_SOURCE}" ]]; then
		install -m 0644 "${ENV_TEMPLATE_SOURCE}" "${INSTALL_ROOT}/config/aurora.env.example"
	fi
	if [[ -f "${RSYSLOG_TEMPLATE_SOURCE}" ]]; then
		install -m 0644 "${RSYSLOG_TEMPLATE_SOURCE}" "${INSTALL_ROOT}/deploy/templates/rsyslog-aurora.conf.example"
	fi
	if [[ -f "${CRON_TEMPLATE_SOURCE}" ]]; then
		install -m 0644 "${CRON_TEMPLATE_SOURCE}" "${INSTALL_ROOT}/deploy/templates/aurora-maintenance.cron.example"
	fi

	if [[ -f "${INSTALL_ROOT}/config/aurora.env" && "${FORCE_ENV}" -eq 0 ]]; then
		install -m 0644 "${ENV_SOURCE}" "${INSTALL_ROOT}/config/aurora.env.new"
		warn "kept existing ${INSTALL_ROOT}/config/aurora.env; wrote new defaults to aurora.env.new"
	else
		install -m 0644 "${ENV_SOURCE}" "${INSTALL_ROOT}/config/aurora.env"
	fi

	install -m 0755 "${SOURCE_ROOT}/scripts/install-service.sh" "${INSTALL_ROOT}/scripts/install-service.sh"
	install -m 0755 "${SOURCE_ROOT}/scripts/install-maintenance-cron.sh" "${INSTALL_ROOT}/scripts/install-maintenance-cron.sh"
	if [[ -f "${FILENAME_IOC_SOURCE}" ]]; then
		install -m 0644 "${FILENAME_IOC_SOURCE}" "${INSTALL_ROOT}/resources/iocs/filename-iocs.txt"
	else
		warn "filename IOCs not found at ${FILENAME_IOC_SOURCE}; filename IOC matching may be disabled"
	fi
	if [[ -f "${C2_IOC_SOURCE}" ]]; then
		install -m 0644 "${C2_IOC_SOURCE}" "${INSTALL_ROOT}/resources/iocs/c2-iocs.txt"
	else
		warn "C2 IOCs not found at ${C2_IOC_SOURCE}; C2 IOC matching may be disabled"
	fi

	install -m 0644 "${INSTALL_ROOT}/deploy/aurora.service" "/etc/systemd/system/aurora.service"
}

sync_local_rules() {
	local source="$1"
	local source_linux="${source}"

	if [[ -d "${source}/rules/linux" ]]; then
		source_linux="${source}/rules/linux"
	fi
	[[ -d "${source_linux}" ]] || die "--rules-source must be a rules/linux directory or parent"

	local target="${INSTALL_ROOT}/sigma-rules/rules/linux"
	local backup="${target}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
	local staged="${target}.new.$(date -u +%Y%m%dT%H%M%SZ)"

	mkdir -p "${staged}"
	cp -a "${source_linux}/." "${staged}/"
	if [[ -d "${target}" ]]; then
		mv "${target}" "${backup}"
		log "backed up existing rules to ${backup}"
	fi
	mv "${staged}" "${target}"
	log "installed local Sigma rules into ${target}"
}

update_signatures_remote() {
	if [[ "${SKIP_SIGNATURE_UPDATE}" -eq 1 ]]; then
		log "signature update skipped (--skip-signature-update)"
		return
	fi
	if [[ ! -x "${INSTALL_ROOT}/aurora-util" ]]; then
		warn "cannot update signatures: ${INSTALL_ROOT}/aurora-util not present"
		return
	fi
	"${INSTALL_ROOT}/aurora-util" update-signatures --rules-dir "${INSTALL_ROOT}/sigma-rules/rules/linux"
}

enable_and_start_service() {
	systemctl daemon-reload

	if [[ "${ENABLE_SERVICE}" -eq 1 ]]; then
		systemctl enable aurora
	else
		log "service enable skipped (--disable-service)"
	fi

	if [[ "${START_SERVICE}" -eq 1 ]]; then
		systemctl restart aurora
		systemctl --no-pager --full status aurora || true
	else
		log "service start/restart skipped (--no-start)"
	fi
}

main() {
	parse_args "$@"
	require_root

	local os_family
	os_family="$(detect_os_family)"
	log "detected distro family: ${os_family}"

	install_deps "${os_family}"
	install_files

	if [[ -n "${RULES_SOURCE_DIR}" ]]; then
		sync_local_rules "${RULES_SOURCE_DIR}"
	else
		update_signatures_remote
	fi

	enable_and_start_service

	log "installation complete"
	log "service unit: /etc/systemd/system/aurora.service"
	log "runtime config: ${INSTALL_ROOT}/config/aurora.env"
	log "maintenance helper: ${INSTALL_ROOT}/scripts/install-maintenance-cron.sh"
}

main "$@"
