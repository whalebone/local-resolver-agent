#!/bin/bash

#mkdir -p /opt/agent/certs && chmod o-rwx /opt/whalebone/certs

#echo ${WHALEBONE_CA_CRT_BASE64} | base64 -d  > /opt/whalebone/certs/ca.crt
echo ${CLIENT_CRT_BASE64} | base64 -d > /opt/agent/certs/client.crt
echo ${CLIENT_KEY_BASE64} | base64 -d > /opt/agent/certs/client.key

cat /opt/agent/certs/client.crt /opt/agent/certs/client.key > /opt/agent/certs/client.pem
cp /opt/agent/cli.sh /etc/whalebone/cli/


python3 lr_agent_app.py
