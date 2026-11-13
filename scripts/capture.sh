#!/bin/bash
# Build the image and record a baseline and an incident capture, from the repo root.
# Usage: scripts/capture.sh baseline incident
# Needs Docker with a kernel that has BTF and tracefs (tested on Docker Desktop WSL2).
set -eu
export MSYS_NO_PATHCONV=1
here="$(pwd -W 2>/dev/null || pwd)"
net=ptreelab
image=ptree-lab:latest

docker build -q -t "$image" docker > /dev/null
docker network inspect "$net" > /dev/null 2>&1 || docker network create --internal "$net" > /dev/null
cleanup() { docker rm -f ptreelab-listener > /dev/null 2>&1 || true; docker network rm "$net" > /dev/null 2>&1 || true; }
trap cleanup EXIT

docker rm -f ptreelab-listener > /dev/null 2>&1 || true
docker run -d --name ptreelab-listener --network "$net" --network-alias listener \
  -v "$here/scenario:/lab/scenario:ro" "$image" \
  bash -c 'nc -lk -p 4444 > /dev/null & cd /lab/scenario/payloads && exec python3 -m http.server 8000' > /dev/null
sleep 2

for name in "$@"; do
  # --pid=host: the eBPF programs report host PIDs, so Sysmon must see the host /proc.
  docker run --rm --privileged --pid=host --network "$net" --hostname lab-sensor \
    -v "$here/configs:/configs:ro" -v "$here/scenario:/lab/scenario:ro" \
    -v "$here/data:/out" "$image" bash /lab/scenario/run_capture.sh "$name"
done
