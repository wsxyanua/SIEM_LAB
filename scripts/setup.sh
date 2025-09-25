#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="mini-siem.service"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
PROJECT_DIR="/home/logntsu/siem_lab"
PYTHON="${PROJECT_DIR}/.venv/bin/python"

usage() {
	echo "Usage: $0 [--ensure-firewall] [--install-service] [--remove-service]" >&2
	exit 1
}

ensure_firewall() {
	${PYTHON} -m mini_siem.cli ensure-firewall || true
}

install_service() {
	if [ ! -x "${PYTHON}" ]; then
		echo "Python venv not found; please create and install requirements first" >&2
		exit 1
	fi
	cat >"${UNIT_PATH}" <<EOF
[Unit]
Description=Mini SIEM SSH brute-force detector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PYTHON} -m mini_siem
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	echo "Installed ${UNIT_PATH}"
}

remove_service() {
	systemctl stop ${SERVICE_NAME} || true
	systemctl disable ${SERVICE_NAME} || true
	rm -f "${UNIT_PATH}" || true
	systemctl daemon-reload
	echo "Removed ${UNIT_PATH}"
}

if [ $# -eq 0 ]; then
	usage
fi

while [ $# -gt 0 ]; do
	case "$1" in
		--ensure-firewall)
			ensure_firewall
			shift
			;;
		--install-service)
			install_service
			shift
			;;
		--remove-service)
			remove_service
			shift
			;;
		*)
			usage
			;;
	esac
done
