#!/bin/sh

BRANCH_NAME=v$(curl -s https://nitpanel.net/version.txt | sed -e 's|{"version":"||g' -e 's|","build":|.|g'| sed 's:}*$::')

rm -f /usr/local/nitpanel_upgrade.sh
wget -O /usr/local/nitpanel_upgrade.sh https://raw.githubusercontent.com/usmannasir/nitpanel/$BRANCH_NAME/nitpanel_upgrade.sh 2>/dev/null
chmod 700 /usr/local/nitpanel_upgrade.sh
/usr/local/nitpanel_upgrade.sh
