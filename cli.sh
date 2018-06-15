#!/bin/bash
docker exec -t lr-agent python3 /opt/whalebone/cli.py "$1" --args "$2" "$3" "$4"
