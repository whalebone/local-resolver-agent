#!/bin/bash
set -e

SOCK_DOCKER_GID=`ls -ng /var/run/docker.sock | cut -f3 -d' '`

if ! groups agent | grep -q docker; then
  groupadd -g ${SOCK_DOCKER_GID} -o hostdocker
  usermod -a -G hostdocker agent
fi

chown agent -R /etc/whalebone/  && chmod ug+rwxs -R /etc/whalebone/
chown agent -R /opt/agent/  && chmod ug+rwxs -R /opt/agent/

# Execute process
exec /usr/local/bin/gosu agent "$@"