#!/bin/bash

# NitPanel - Auto Update Script
# Usage: bash <(curl -s https://nitpanel.netihot.com/update.sh)

NITPANEL_DIR="/usr/local/NitPanel"
BACKUP_DIR="/usr/local/NitPanel-backup"
VERSION_FILE="$NITPANEL_DIR/version.txt"

echo "================================================"
echo "   NitPanel - Auto Update"
echo "================================================"

# Backup trước khi update
echo "[1/4] Backing up current version..."
cp -r $NITPANEL_DIR $BACKUP_DIR-$(date +%Y%m%d-%H%M%S)
echo "✅ Backup done!"

# Pull code mới nhất
echo "[2/4] Pulling latest NitPanel..."
cd $NITPANEL_DIR
git pull origin main
echo "✅ Code updated!"

# Rebranding lại sau update
echo "[3/4] Applying NitPanel branding..."
find . -type f \( -name "*.py" -o -name "*.html" -o -name "*.sh" \) \
    -exec sed -i 's/CyberPanel/NitPanel/g' {} +
find . -type f \( -name "*.py" -o -name "*.html" -o -name "*.sh" \) \
    -exec sed -i 's/cyberpanel/nitpanel/g' {} +
echo "✅ Branding applied!"

# Restart service
echo "[4/4] Restarting NitPanel services..."
systemctl restart nitpanel-server
systemctl restart lscpd 2>/dev/null || true
echo "✅ Services restarted!"

echo ""
echo "================================================"
echo "  ✅ NitPanel Updated Successfully!"
echo "================================================"
echo "  Backup saved at: $BACKUP_DIR-$(date +%Y%m%d)"
echo "================================================"
