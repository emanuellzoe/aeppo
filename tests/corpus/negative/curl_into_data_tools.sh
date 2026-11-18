#!/bin/sh
curl -fsS "http://127.0.0.1:$PORT/stats" | python3 -m json.tool
curl -fsS https://example.invalid/data.json | jq .version
curl -fsS https://example.invalid/data.json | node scripts/report.js
curl -fsS https://example.invalid/x | sh -c 'cat > out.txt'
