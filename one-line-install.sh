#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NITPANEL — One-Line Installer (v1.3.1)                     ║
# ║                                                              ║
# ║  Cách dùng:                                                  ║
# ║    curl -fsSL https://raw.githubusercontent.com/\            ║
# ║      trongthangno9-nitpanel/nitpanell/main/\                  ║
# ║      one-line-install.sh | sudo bash                         ║
# ╚══════════════════════════════════════════════════════════════╝
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[OK]${NC} $1"; }
info() { echo -e "${CYAN}[..]${NC} $1"; }
warn() { echo -e "${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

echo -e "${CYAN}${BOLD}"
cat << 'LOGO'
  _   _ ___ _____ ____   _    _   _ _____ _
 | \ | |_ _|_   _|  _ \ / \  | \ | | ____| |
 |  \| || |  | | | |_) / _ \ |  \| |  _| | |
 | |\  || |  | | |  __/ ___ \| |\  | |___| |___
 |_| \_|___| |_| |_| /_/   \_\_| \_|_____|_____|

 One-Line Installer  —  v1.3.0
 PHP / Nginx / MySQL / Fail2ban Panel — AlmaLinux 9/10
LOGO
echo -e "${NC}"

# ── Checks ────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && err "Cần root: chạy lại với 'sudo bash' phía cuối lệnh"

if ! grep -qi "almalinux\|centos\|rhel\|rocky" /etc/os-release 2>/dev/null; then
  warn "Script này dành cho AlmaLinux/RHEL/Rocky. Tiếp tục? (y/N)"
  read -r ans; [[ "$ans" != "y" ]] && exit 1
fi

# ── Settings ──────────────────────────────────────────────────
GITHUB_USER="trongthangno9-nitpanel"
GITHUB_REPO="nitpanell"
GITHUB_BRANCH="main"

INSTALL_DIR="/opt/nitpanel_src"
PANEL_DIR="/opt/nitpanel"
CONFIG_DIR="/etc/nitpanel"
LOG_DIR="/var/log/nitpanel"
CREDS_FILE="$CONFIG_DIR/credentials.txt"
RELEASE_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/releases/latest/download/nitpanel-almalinux.tar.gz"
SOURCE_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.tar.gz"

mkdir -p "$PANEL_DIR" "$CONFIG_DIR" "$LOG_DIR"
mkdir -p /etc/nginx/conf.d /var/www /run/php-fpm
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
chmod 700 "$CONFIG_DIR"

# ── Install dependencies ──────────────────────────────────────
info "Cài dependencies..."
dnf install -y --setopt=logdir=/tmp gcc openssl-devel pkgconfig curl tar 2>&1 | tail -3 || true

# openssl-devel có thể kéo openssl lên version mới — nếu openssh-server
# vẫn link openssl cũ thì sshd không restart được sau reboot, mất SSH.
info "Đồng bộ openssh với openssl..."
dnf upgrade -y --setopt=logdir=/tmp openssh openssh-server openssh-clients 2>&1 | tail -3 || true
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true

# ── Try prebuilt binary first ─────────────────────────────────
USE_PREBUILT=false
if curl -fsSL --head "$RELEASE_URL" 2>/dev/null | grep -q "200"; then
  info "Tìm thấy prebuilt binary, đang tải..."
  if curl -fsSL "$RELEASE_URL" | tar -xzf - -C "$PANEL_DIR" 2>/dev/null; then
    if [ -f "$PANEL_DIR/nitpanel" ]; then
      chmod 755 "$PANEL_DIR/nitpanel"
      USE_PREBUILT=true
      log "Đã tải prebuilt binary"
    fi
  fi
fi

# ── Build from source if no prebuilt ──────────────────────────
if [ "$USE_PREBUILT" = "false" ]; then
  info "Không có prebuilt, sẽ build từ source (~5-10 phút)..."

  if ! command -v cargo &>/dev/null && [ ! -f "$HOME/.cargo/bin/cargo" ]; then
    info "Cài Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
      sh -s -- -y --default-toolchain stable --no-modify-path
  fi
  export PATH="$HOME/.cargo/bin:$PATH"
  source "$HOME/.cargo/env" 2>/dev/null || true
  command -v cargo &>/dev/null || err "Không tìm thấy cargo. Thử: source ~/.cargo/env"
  log "Rust: $(rustc --version)"

  info "Tải source code..."
  rm -rf "$INSTALL_DIR" && mkdir -p "$INSTALL_DIR"
  if ! curl -fsSL "$SOURCE_URL" | tar -xzf - --strip-components=1 -C "$INSTALL_DIR" 2>/dev/null; then
    err "Không tải được source. Kiểm tra kết nối mạng."
  fi

  info "Build NITPANEL..."
  cd "$INSTALL_DIR"
  cargo build --release 2>&1 | grep -E "^(Compiling|Finished|error)" || true
  [ ! -f "target/release/nitpanel" ] && err "Build thất bại."

  install -m 0755 -o root -g root target/release/nitpanel "$PANEL_DIR/nitpanel"
  log "Build xong: $(du -sh $PANEL_DIR/nitpanel | cut -f1)"
fi

# ── JWT secret ────────────────────────────────────────────────
UNIT_FILE="/etc/systemd/system/nitpanel.service"
if [ -f "$UNIT_FILE" ] && grep -q "NITPANEL_JWT_SECRET=" "$UNIT_FILE" 2>/dev/null; then
  JWT_SECRET=$(grep "NITPANEL_JWT_SECRET=" "$UNIT_FILE" | sed 's/.*NITPANEL_JWT_SECRET=//;s/"$//')
else
  JWT_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64)
fi

# ── Admin password ────────────────────────────────────────────
IS_FRESH=false
if [ ! -f "$CONFIG_DIR/state.json" ]; then
  IS_FRESH=true
  ADMIN_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 18)
  info "Tạo bcrypt hash cho mật khẩu admin..."
  HASH=$("$PANEL_DIR/nitpanel" hash "$ADMIN_PASS" 2>/dev/null || true)
  if [ -z "$HASH" ] || [[ "$HASH" != "\$2"* ]]; then
    err "Không tạo được password hash. Kiểm tra binary nitpanel."
  fi
  cat > "$CONFIG_DIR/state.json" <<STATEEOF
{
  "websites": [],
  "admin_password_hash": "$HASH",
  "login_attempts": {},
  "fail2ban": {
    "enabled": false,
    "ban_time": 3600,
    "find_time": 600,
    "max_retry": 5,
    "whitelist_ips": []
  }
}
STATEEOF
  chmod 600 "$CONFIG_DIR/state.json"
  log "state.json mới với bcrypt hash"
else
  ADMIN_PASS="(giữ từ lần cài trước)"
  [ -f "$CREDS_FILE" ] && ADMIN_PASS=$(grep "^Password:" "$CREDS_FILE" 2>/dev/null | awk '{print $2}')
  log "Giữ password cũ"
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP="<server-ip>"
cat > "$CREDS_FILE" <<CREDSEOF
# NITPANEL Credentials — $(date)
URL:      http://$IP:8765
Password: $ADMIN_PASS
CREDSEOF
chmod 600 "$CREDS_FILE"

# ── Systemd ───────────────────────────────────────────────────
cat > "$UNIT_FILE" <<UNITEOF
[Unit]
Description=NITPANEL — PHP/Nginx/MySQL/Fail2ban Control Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PANEL_DIR/nitpanel
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=$PANEL_DIR
Environment="RUST_LOG=nitpanel=info,actix_web=warn"
Environment="NITPANEL_JWT_SECRET=$JWT_SECRET"
Environment="NITPANEL_BIND=0.0.0.0:8765"
Environment="NITPANEL_TRUST_XFF=0"
StandardOutput=append:$LOG_DIR/panel.log
StandardError=append:$LOG_DIR/error.log

NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNITEOF
chmod 644 "$UNIT_FILE"

systemctl daemon-reload
systemctl enable nitpanel --quiet
systemctl restart nitpanel
sleep 2

# Firewall
if command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-port=8765/tcp --quiet 2>/dev/null || true
  firewall-cmd --permanent --add-service=http  --quiet 2>/dev/null || true
  firewall-cmd --permanent --add-service=https --quiet 2>/dev/null || true
  firewall-cmd --reload --quiet 2>/dev/null || true
fi

# SSL auto-renew cron (idempotent)
cat > /etc/cron.d/nitpanel-certbot-renew <<'RENEWEOF'
17 3 * * * root certbot renew --quiet --no-self-upgrade --post-hook "systemctl reload nginx 2>/dev/null" >> /var/log/nitpanel/certbot-renew.log 2>&1
RENEWEOF
chmod 644 /etc/cron.d/nitpanel-certbot-renew
systemctl enable --now certbot-renew.timer 2>/dev/null || true
systemctl enable --now certbot.timer       2>/dev/null || true
systemctl enable --now crond 2>/dev/null || true

# ── Done ──────────────────────────────────────────────────────
systemctl is-active nitpanel --quiet && STATUS="${GREEN}RUNNING${NC}" || STATUS="${RED}CHECK LOGS${NC}"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}${BOLD}      NITPANEL — Cài đặt thành công!               ${NC}${GREEN}║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Panel:    ${CYAN}http://${IP}:8765${NC}"
if [ "$IS_FRESH" = true ]; then
echo -e "${GREEN}║${NC}  Password: ${YELLOW}${ADMIN_PASS}${NC}  ${RED}← LƯU LẠI!${NC}"
echo -e "${GREEN}║${NC}  Đã lưu:  $CREDS_FILE"
else
echo -e "${GREEN}║${NC}  Password: ${YELLOW}Giữ từ lần cài trước${NC}"
fi
echo -e "${GREEN}║${NC}  Status:   ${STATUS}"
echo -e "${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Sau khi đăng nhập:"
echo -e "${GREEN}║${NC}  → Cài Stack: Nginx + MySQL 9 + PHP + Certbot"
echo -e "${GREEN}║${NC}  → Đổi mật khẩu admin (Settings)"
echo -e "${GREEN}║${NC}  → Bật Fail2ban (tab Bảo mật)"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}journalctl -u nitpanel -f${NC}  (log realtime)"
echo -e "  ${CYAN}cat $CREDS_FILE${NC}            (xem password)"
echo ""
