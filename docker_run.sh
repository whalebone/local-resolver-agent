#!/bin/bash

export WHALEBONE_CLIENT_CRT_BASE64=''
export WHALEBONE_CLIENT_KEY_BASE64=''
export WHALEBONE_PORTAL_ADDRESS='wss://localhost:8443/wsproxy/ws'

docker run -t -i \
-e WHALEBONE_CLIENT_CRT_BASE64 \
-e WHALEBONE_CLIENT_KEY_BASE64 \
-e WHALEBONE_PORTAL_ADDRESS \
-v /var/run/docker.sock:/var/run/docker.sock \
lr-agent