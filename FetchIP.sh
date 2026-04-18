Server_IP=$(curl --silent --max-time 30 -4 https://nitpanel.sh/?ip)
echo "$Server_IP" > "/etc/nitpanel/machineIP"