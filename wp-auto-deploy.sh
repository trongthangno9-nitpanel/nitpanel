#!/bin/bash

# NitPanel - WordPress Auto Deploy
# Usage: bash wp-auto-deploy.sh domain.com db_name db_user db_pass

DOMAIN=$1
DB_NAME=$2
DB_USER=$3
DB_PASS=$4
WP_PATH="/home/$DOMAIN/public_html"

echo "================================================"
echo "  NitPanel - WordPress Auto Deploy"
echo "  Domain: $DOMAIN"
echo "================================================"

# Kiểm tra tham số
if [ -z "$DOMAIN" ] || [ -z "$DB_NAME" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASS" ]; then
    echo "Usage: bash wp-auto-deploy.sh domain.com db_name db_user db_pass"
    exit 1
fi

# Download WordPress
echo "[1/6] Downloading WordPress..."
cd /tmp
curl -s -O https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz

# Copy vào public_html
echo "[2/6] Installing WordPress files..."
cp -r /tmp/wordpress/* $WP_PATH/
rm -rf /tmp/wordpress /tmp/latest.tar.gz

# Tạo wp-config.php
echo "[3/6] Configuring wp-config.php..."
cp $WP_PATH/wp-config-sample.php $WP_PATH/wp-config.php

sed -i "s/database_name_here/$DB_NAME/" $WP_PATH/wp-config.php
sed -i "s/username_here/$DB_USER/" $WP_PATH/wp-config.php
sed -i "s/password_here/$DB_PASS/" $WP_PATH/wp-config.php
sed -i "s/localhost/localhost/" $WP_PATH/wp-config.php

# Thêm Security Keys tự động
echo "[4/6] Generating security keys..."
KEYS=$(curl -s https://api.wordpress.org/secret-key/1.1/salt/)
sed -i "/AUTH_KEY/d" $WP_PATH/wp-config.php
sed -i "/SECURE_AUTH_KEY/d" $WP_PATH/wp-config.php
sed -i "/LOGGED_IN_KEY/d" $WP_PATH/wp-config.php
sed -i "/NONCE_KEY/d" $WP_PATH/wp-config.php
sed -i "/AUTH_SALT/d" $WP_PATH/wp-config.php
sed -i "/SECURE_AUTH_SALT/d" $WP_PATH/wp-config.php
sed -i "/LOGGED_IN_SALT/d" $WP_PATH/wp-config.php
sed -i "/NONCE_SALT/d" $WP_PATH/wp-config.php
echo "$KEYS" >> $WP_PATH/wp-config.php

# Cài WP-CLI
echo "[5/6] Installing WP-CLI..."
if [ ! -f /usr/local/bin/wp ]; then
    curl -s -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
fi

# Auto install WordPress
echo "[6/6] Running WordPress installation..."
WP_ADMIN_PASS=$(openssl rand -base64 12)
WP_ADMIN_EMAIL="admin@$DOMAIN"

wp core install \
    --path=$WP_PATH \
    --url="https://$DOMAIN" \
    --title="$DOMAIN" \
    --admin_user="nitadmin" \
    --admin_password="$WP_ADMIN_PASS" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --allow-root

# Cài plugin cơ bản
echo "Installing essential plugins..."
wp plugin install litespeed-cache --activate --allow-root --path=$WP_PATH
wp plugin install wordfence --activate --allow-root --path=$WP_PATH
wp plugin install wp-mail-smtp --allow-root --path=$WP_PATH

# Set permissions
chown -R nobody:nobody $WP_PATH
chmod -R 755 $WP_PATH

echo ""
echo "================================================"
echo "  ✅ WordPress Installed Successfully!"
echo "================================================"
echo "  URL      : https://$DOMAIN"
echo "  Admin    : https://$DOMAIN/wp-admin"
echo "  Username : nitadmin"
echo "  Password : $WP_ADMIN_PASS"
echo "  Email    : $WP_ADMIN_EMAIL"
echo "================================================"
echo "  ⚠️  Save your password now!"
echo "================================================"
