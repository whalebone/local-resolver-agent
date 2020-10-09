#!/bin/bash
set -e

# If "-e uid={custom/local user id}" flag is not set for "docker run" command, use 9999 as default
CURRENT_UID=${uid:-9999}

# Notify user about the UID selected
echo "Current UID : $CURRENT_UID"
# Create user called "docker" with selected UID
useradd --shell /bin/bash -u $CURRENT_UID -o -c "" -m agent
# Set "HOME" ENV variable for user's home directory
export HOME=/home/agent

SOCK_DOCKER_GID=`ls -ng /var/run/docker.sock | cut -f3 -d' '`

if ! groups agent | grep -q docker; then
  groupadd -g ${SOCK_DOCKER_GID} -o hostdocker
  usermod -a -G hostdocker agent
fi

chown agent -R /etc/whalebone/  && chmod ug+rwxs -R /etc/whalebone/
chown agent -R /opt/agent/  && chmod ug+rwxs -R /opt/agent/

# Execute process
exec /usr/local/bin/gosu agent "$@"