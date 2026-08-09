#!/bin/bash
set -e

USER="$(openssl rand -hex 10)"
PASS="$(openssl rand -base64 40)"

htpasswd -bc /usr/local/apache2/.htpasswd "$USER" "$PASS"

echo "http user $USER : $PASS"

PASS="$(openssl rand -base64 12)"

echo "admin:$PASS" > /tmp/cgi_users.txt
chown www-data:www-data /tmp/cgi_users.txt && chmod 640 /tmp/cgi_users.txt
touch /tmp/messages.txt && chown www-data:www-data /tmp/messages.txt

echo "cgi admin pass : $PASS"

su ctf -s /bin/bash -c /home/ctf/echo_server &

exec "$@"