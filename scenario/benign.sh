#!/bin/bash
# Normal use of the app plus a nightly-style backup job. Runs inside the sensor container.
rounds="${1:-10}"
for i in $(seq 1 "$rounds"); do
  curl -s -m 3 -o /dev/null "http://127.0.0.1:8080/health"
  curl -s -m 5 -o /dev/null "http://127.0.0.1:8080/ping?host=127.0.0.1"
  if [ $((i % 4)) -eq 0 ]; then
    sh -c "tar czf /tmp/app-backup.tgz /etc/hostname 2>/dev/null; rm -f /tmp/app-backup.tgz"
  fi
  sleep 1
done
