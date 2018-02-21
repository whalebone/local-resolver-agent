#!/bin/bash

mkdir -p /opt/whalebone/certs && chmod o-rwx /opt/whalebone/certs

#echo ${WHALEBONE_CA_CRT_BASE64} | base64 -d  > /opt/whalebone/certs/ca.crt
echo ${WHALEBONE_CLIENT_CRT_BASE64} | base64 -d > /opt/whalebone/certs/client.crt
echo ${WHALEBONE_CLIENT_KEY_BASE64} | base64 -d > /opt/whalebone/certs/client.key

cat /opt/whalebone/certs/client.crt /opt/whalebone/certs/client.key > /opt/whalebone/certs/client.pem

export WHALEBONE_LR_CLIENT_CERT=/opt/whalebone/certs/client.pem

python3 lr_agent_app.py
