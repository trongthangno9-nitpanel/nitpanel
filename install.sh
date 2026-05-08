#!/bin/bash
# ╔══════════════════════════════════════════════════════════╗
# ║         NITPANEL v2.4.0 — AlmaLinux 9/10                ║
# ╚══════════════════════════════════════════════════════════╝

set -o pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
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

 PHP / Nginx / MySQL / Fail2ban Panel
 AlmaLinux 9 / 10  —  v2.4.0
LOGO
echo -e "${NC}"

# ── Checks ─────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && err "Cần root: sudo bash install.sh"

if ! grep -qi "almalinux\|centos\|rhel\|rocky" /etc/os-release 2>/dev/null; then
  warn "Script dành cho AlmaLinux/RHEL. Tiếp tục? (y/N)"
  read -r ans; [[ "$ans" != "y" ]] && exit 1
fi

PANEL_DIR="/opt/nitpanel"
CONFIG_DIR="/etc/nitpanel"
LOG_DIR="/var/log/nitpanel"
CREDS_FILE="$CONFIG_DIR/credentials.txt"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_FILE="/etc/systemd/system/nitpanel.service"

# ── 1. Tạo thư mục ─────────────────────────────────────────
info "Tạo thư mục..."
mkdir -p "$PANEL_DIR" "$CONFIG_DIR" "$LOG_DIR"
mkdir -p /etc/nginx/conf.d /var/www /run/php-fpm
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
chmod 700 "$CONFIG_DIR"
log "Thư mục OK"

# ── 2. Dependencies ────────────────────────────────────────
info "Cài dependencies (gcc, openssl-devel, ...)..."
dnf install -y --setopt=logdir=/tmp gcc openssl-devel pkgconfig curl tar gzip zip unzip 2>&1 | \
  tail -5 || true
log "Dependencies OK"

# ── 2b. Đồng bộ openssh-server với openssl mới ────────────
# openssl-devel có thể kéo openssl lên version mới. Nếu openssh-server
# vẫn link openssl cũ, sshd có thể không restart được sau reboot →
# mất SSH. Upgrade openssh-server ngay để 2 package cùng nhịp.
info "Upgrade openssh-server (đồng bộ với openssl)..."
dnf upgrade -y --setopt=logdir=/tmp openssh openssh-server openssh-clients 2>&1 | \
  tail -3 || true
systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
log "openssh-server đồng bộ"

# ── 3. Rust ────────────────────────────────────────────────
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo &>/dev/null; then
  info "Cài Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --no-modify-path
  source "$HOME/.cargo/env" 2>/dev/null || true
fi
command -v cargo &>/dev/null || err "Không tìm thấy cargo. Thử: source ~/.cargo/env"
log "Rust: $(rustc --version)"

# ── 4. Build ───────────────────────────────────────────────
cd "$SCRIPT_DIR"
if [ -f "target/release/nitpanel" ] && [ "$1" != "--rebuild" ]; then
  log "Binary đã có (thêm --rebuild để build lại)"
else
  info "Build (~5-10 phút lần đầu)..."
  cargo build --release 2>&1 | grep -E "^(Compiling|Finished|error|warning: unused)" || true
  [ ! -f "target/release/nitpanel" ] && err "Build thất bại — chạy 'cargo build --release' để xem chi tiết"
  log "Build OK: $(du -sh target/release/nitpanel | cut -f1)"
fi

# ── 5. Copy binary ─────────────────────────────────────────
install -m 0755 -o root -g root target/release/nitpanel "$PANEL_DIR/nitpanel"
log "Binary: $PANEL_DIR/nitpanel"

# ── 6. JWT Secret ──────────────────────────────────────────
if [ -f "$UNIT_FILE" ] && grep -q "NITPANEL_JWT_SECRET=" "$UNIT_FILE" 2>/dev/null; then
  JWT_SECRET=$(grep "NITPANEL_JWT_SECRET=" "$UNIT_FILE" | sed 's/.*NITPANEL_JWT_SECRET=//;s/"$//')
  log "JWT secret giữ nguyên"
else
  JWT_SECRET=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 64)
  log "JWT secret mới (64 ký tự random)"
fi

# ── 7. Admin Password ──────────────────────────────────────
# Fresh install: random password + bcrypt hash bằng chính binary nitpanel
# Re-install: giữ state.json cũ
IS_FRESH=false
if [ ! -f "$CONFIG_DIR/state.json" ]; then
  IS_FRESH=true
  ADMIN_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 18)
  info "Tạo bcrypt hash cho mật khẩu admin..."
  HASH=$("$PANEL_DIR/nitpanel" hash "$ADMIN_PASS" 2>/dev/null || true)
  if [ -z "$HASH" ] || [[ "$HASH" != "\$2"* ]]; then
    err "Không tạo được password hash. Kiểm tra binary: $PANEL_DIR/nitpanel hash test"
  fi
  # Write state.json with proper bcrypt hash
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
  log "state.json tạo với bcrypt hash"
else
  if [ -f "$CREDS_FILE" ]; then
    ADMIN_PASS=$(grep "^Password:" "$CREDS_FILE" 2>/dev/null | awk '{print $2}')
  fi
  [ -z "$ADMIN_PASS" ] && ADMIN_PASS="(giữ từ state.json)"
  log "Giữ password cũ"
fi

# ── Lưu credentials ────────────────────────────────────────
IP=$(curl -4 -s ifconfig.me 2>/dev/null || curl -4 -s icanhazip.com 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
[ -z "$IP" ] && IP="<server-ip>"
cat > "$CREDS_FILE" <<CREDSEOF
# NITPANEL Credentials — $(date)
# Giữ file này tuyệt mật! (chmod 600)
URL:      http://$IP:8765
Password: $ADMIN_PASS
CREDSEOF
chmod 600 "$CREDS_FILE"

# ── 8. Systemd service ─────────────────────────────────────
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

# --- security hardening (compatible with most VPS) ---
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

# ── 9. Start service ───────────────────────────────────────
systemctl daemon-reload
systemctl enable nitpanel --quiet
systemctl stop  nitpanel 2>/dev/null || true
sleep 1
systemctl start nitpanel
sleep 2

if systemctl is-active nitpanel --quiet; then
  log "Service NITPANEL đang chạy"
else
  warn "Service chưa start, log gần nhất:"
  journalctl -u nitpanel -n 15 --no-pager 2>/dev/null || tail -20 "$LOG_DIR/error.log" 2>/dev/null
fi

# ── 10. Firewall ───────────────────────────────────────────
if command -v firewall-cmd &>/dev/null; then
  firewall-cmd --permanent --add-port=8765/tcp --quiet 2>/dev/null || true
  firewall-cmd --permanent --add-service=http  --quiet 2>/dev/null || true
  firewall-cmd --permanent --add-service=https --quiet 2>/dev/null || true
  firewall-cmd --reload --quiet 2>/dev/null || true
  log "Firewall: 8765, 80, 443 mở"
fi

# ── 10b. SSL auto-renew (idempotent) ───────────────────────
# certbot renew duyệt tất cả cert trong /etc/letsencrypt/live và gia hạn
# cert nào còn dưới 30 ngày → cron 1 dòng cover toàn bộ domain.
cat > /etc/cron.d/nitpanel-certbot-renew <<'RENEWEOF'
# m h dom mon dow user command
17 3 * * * root certbot renew --quiet --no-self-upgrade --post-hook "systemctl reload nginx 2>/dev/null" >> /var/log/nitpanel/certbot-renew.log 2>&1
RENEWEOF
chmod 644 /etc/cron.d/nitpanel-certbot-renew
# Enable systemd timer làm backup (certbot RPM thường có sẵn timer)
systemctl enable --now certbot-renew.timer 2>/dev/null || true
systemctl enable --now certbot.timer       2>/dev/null || true
# Đảm bảo crond chạy
systemctl enable --now crond 2>/dev/null || true
log "SSL auto-renew: cron 3:17 mỗi ngày + systemd timer (nếu có)"

# ── 11. Summary ────────────────────────────────────────────
STATUS=$(systemctl is-active nitpanel 2>/dev/null)

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${BOLD}    NITPANEL v2.4.0 — Cài đặt thành công!         ${NC}${GREEN}║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  URL:      ${CYAN}http://${IP}:8765${NC}"
if [ "$IS_FRESH" = true ]; then
echo -e "${GREEN}║${NC}  Password: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "${GREEN}║${NC}  ${RED}(LƯU PASSWORD! Đã lưu: $CREDS_FILE)${NC}"
else
echo -e "${GREEN}║${NC}  Password: ${YELLOW}Giữ nguyên từ lần cài trước${NC}"
echo -e "${GREEN}║${NC}  (Xem: cat $CREDS_FILE)"
fi
echo -e "${GREEN}║${NC}  Status:   ${STATUS}"
echo -e "${GREEN}╠════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Vào panel → 'Cài Stack' để cài:"
echo -e "${GREEN}║${NC}  Nginx + MySQL 9 + PHP 8.4 + Certbot + Fail2ban"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}KHUYẾN NGHỊ BẢO MẬT:${NC}"
echo -e "  • Đổi mật khẩu admin sau khi đăng nhập (Settings)"
echo -e "  • Đóng port 8765 khỏi internet, dùng SSH tunnel:"
echo -e "    ${CYAN}firewall-cmd --remove-port=8765/tcp --permanent && firewall-cmd --reload${NC}"
echo -e "    ${CYAN}ssh -L 8765:localhost:8765 root@${IP}${NC}"
echo -e "  • Bật Fail2ban trong panel (tab Bảo mật)"
echo ""
echo -e "  ${CYAN}journalctl -u nitpanel -f${NC}    (xem log)"
echo -e "  ${CYAN}cat $CREDS_FILE${NC}    (xem password)"
echo ""
