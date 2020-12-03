#!/bin/bash
docker exec -t lr-agent python3 /opt/agent/cli.py "$1" --args "$2" "$3" "$4"
