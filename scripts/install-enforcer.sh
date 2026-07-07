#!/usr/bin/env bash
# Installs the Warden enforcer binary as a systemd service on the host.
# Must run as root. Requires: systemd, nftables, /dev/kvm (Firecracker) or gVisor runtime.
#
# Usage: sudo ./scripts/install-enforcer.sh

set -euo pipefail

ENFORCER_BIN="${ENFORCER_BIN:-./enforcer/bin/warden-enforcer}"
INSTALL_PATH="/usr/local/bin/warden-enforcer"
SERVICE_NAME="warden-enforcer"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
SOCKET_DIR="/run/warden-enforcer"
ENFORCER_PORT="${ENFORCER_PORT:-9090}"

if [[ $EUID -ne 0 ]]; then
  echo "error: must run as root" >&2
  exit 1
fi

if ! id -u warden &>/dev/null; then
  echo "Creating warden system user"
  useradd --system --no-create-home --shell /sbin/nologin warden
fi

if [[ ! -f "$ENFORCER_BIN" ]]; then
  echo "error: enforcer binary not found at $ENFORCER_BIN" >&2
  echo "       build with: cd enforcer && go build -o bin/warden-enforcer ./cmd/warden-enforcer" >&2
  exit 1
fi

echo "Installing enforcer binary to $INSTALL_PATH"
install -m 0755 "$ENFORCER_BIN" "$INSTALL_PATH"

echo "Creating socket directory $SOCKET_DIR"
mkdir -p "$SOCKET_DIR"
chown warden:warden "$SOCKET_DIR"
chmod 0750 "$SOCKET_DIR"

echo "Writing systemd unit $SERVICE_FILE"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Warden Egress Enforcer
After=network.target nftables.service

[Service]
Type=simple
User=warden
Group=warden
ExecStart=${INSTALL_PATH} --port ${ENFORCER_PORT} --socket ${SOCKET_DIR}/api.sock
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo "Enforcer installed and started. Status:"
systemctl status "$SERVICE_NAME" --no-pager
