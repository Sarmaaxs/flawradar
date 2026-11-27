#!/usr/bin/env bash
# One way to put a release on the server. Run it ON THE SERVER, from anywhere inside the project:
#   ./scripts/deploy.sh
# It refuses to continue if anything looks off, so a bad push cannot reach the live site.
set -euo pipefail
cd "$(dirname "$0")/.."

git fetch origin main
# Fast-forward only: if someone edited files on the server by hand, this stops and says so.
git merge --ff-only origin/main
npm test --silent

if systemctl list-unit-files 2>/dev/null | grep -q '^flawradar'; then
  sudo systemctl restart flawradar
elif command -v pm2 >/dev/null 2>&1 && pm2 describe flawradar >/dev/null 2>&1; then
  pm2 restart flawradar
elif [ -f docker-compose.yml ] || [ -f compose.yaml ] || [ -f compose.yml ]; then
  docker compose up -d --build
else
  echo "No service found (systemd, pm2 or docker compose). Restart it your usual way, then check /api/health."
  exit 1
fi

sleep 3
curl -fsS "http://127.0.0.1:${PORT:-3000}/api/health" && echo "  <- healthy"
echo "Deployed $(git rev-parse --short HEAD)."
