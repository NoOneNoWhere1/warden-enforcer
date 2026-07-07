#!/usr/bin/env bash
# Runs the real end-to-end demo in a privileged container wired to the Rekor
# stack and Postgres, then paces the genuine output to a readable cadence for
# GIF capture (demo/gif/demo.tape). The output is live and real — only the
# inter-line delay is added, so a human can follow the run.
#
# Prereqs: `warden-demo` image built (demo/gif/Dockerfile) and the compose
# stack up (postgres + `--profile gate` rekor-server) on network infra_default.
set -uo pipefail

docker run --rm --privileged --network infra_default \
    -e ENFORCER_REKOR_URL=http://rekor-server:3000 \
    -e POSTGRES_HOST=postgres -e POSTGRES_PORT=5432 -e POSTGRES_PASSWORD=warden \
    warden-demo \
  | while IFS= read -r line; do printf '%s\n' "$line"; sleep 0.035; done
