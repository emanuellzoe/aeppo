#!/bin/sh
# wait-for-it style health check and safe download
(echo -n > /dev/tcp/$HOST/$PORT) >/dev/null 2>&1
curl -fsSL -o install.sh https://example.invalid/install.sh
# curl https://example.invalid/x | sh is mentioned in a comment only
crontab -l
base64 -d payload.b64 > payload.bin
