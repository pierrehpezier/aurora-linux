#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?VERSION is required}"
: "${GOARCH:?GOARCH is required}"
: "${BINARY_PATH:?BINARY_PATH is required}"
: "${SIGMA_REPO_DIR:?SIGMA_REPO_DIR is required}"
UTILITY_BINARY_PATH="${UTILITY_BINARY_PATH:-}"

DIST_DIR="${DIST_DIR:-dist}"
PACKAGE_NAME="aurora-${VERSION}-linux-${GOARCH}"

if [[ ! -f "${BINARY_PATH}" ]]; then
	echo "binary not found at ${BINARY_PATH}" >&2
	exit 1
fi

if [[ -n "${UTILITY_BINARY_PATH}" && ! -f "${UTILITY_BINARY_PATH}" ]]; then
	echo "utility binary not found at ${UTILITY_BINARY_PATH}" >&2
	exit 1
fi

if [[ ! -d "${SIGMA_REPO_DIR}/rules/linux" ]]; then
	echo "Sigma rules directory not found at ${SIGMA_REPO_DIR}/rules/linux" >&2
	exit 1
fi

mkdir -p "${DIST_DIR}"

stage_dir="$(mktemp -d)"
trap 'rm -rf "${stage_dir}"' EXIT

package_root="${stage_dir}/${PACKAGE_NAME}"
install_root="${package_root}/opt/aurora-linux"

mkdir -p \
	"${install_root}/config" \
	"${install_root}/deploy" \
	"${install_root}/deploy/templates" \
	"${install_root}/scripts" \
	"${install_root}/sigma-rules/rules"

install -m 0755 "${BINARY_PATH}" "${install_root}/aurora"
if [[ -n "${UTILITY_BINARY_PATH}" ]]; then
	install -m 0755 "${UTILITY_BINARY_PATH}" "${install_root}/aurora-util"
fi
install -m 0644 deploy/aurora.service "${install_root}/deploy/aurora.service"
install -m 0644 deploy/aurora.env "${install_root}/config/aurora.env"
install -m 0644 deploy/templates/aurora.env.example "${install_root}/config/aurora.env.example"
install -m 0644 deploy/templates/rsyslog-aurora.conf.example "${install_root}/deploy/templates/rsyslog-aurora.conf.example"
install -m 0644 deploy/templates/aurora-maintenance.cron.example "${install_root}/deploy/templates/aurora-maintenance.cron.example"
install -m 0755 scripts/install-service.sh "${install_root}/scripts/install-service.sh"
install -m 0755 scripts/install-maintenance-cron.sh "${install_root}/scripts/install-maintenance-cron.sh"
cp -a "${SIGMA_REPO_DIR}/rules/linux" "${install_root}/sigma-rules/rules/"

sigma_sha="unknown"
if git -C "${SIGMA_REPO_DIR}" rev-parse HEAD >/dev/null 2>&1; then
	sigma_sha="$(git -C "${SIGMA_REPO_DIR}" rev-parse HEAD)"
fi

cat >"${install_root}/sigma-rules/SOURCE.txt" <<EOF
repo=https://github.com/SigmaHQ/sigma
commit=${sigma_sha}
included_path=rules/linux
EOF

tar -C "${stage_dir}" -czf "${DIST_DIR}/${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
echo "wrote ${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
