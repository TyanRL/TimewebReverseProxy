#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/TimewebReverseProxy}"
REPO_URL="https://github.com/TyanRL/TimewebReverseProxy.git"

if [[ ! -d "$APP_DIR/.git" ]]; then
  git clone "$REPO_URL" "$APP_DIR"
else
  git -C "$APP_DIR" fetch origin main
  git -C "$APP_DIR" reset --hard origin/main
fi

cd "$APP_DIR"

if [[ ! -f .env ]]; then
  echo "Не найден $APP_DIR/.env. Создайте его на основе env.example и запустите скрипт повторно." >&2
  exit 1
fi

auth_enabled="$(grep -E '^[[:space:]]*AUTH_ENABLED[[:space:]]*=' .env | tail -n 1 | cut -d= -f2- | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' || true)"
if [[ "$auth_enabled" == "true" || "$auth_enabled" == "1" || "$auth_enabled" == "yes" ]] && [[ ! -f clients.json ]]; then
  echo "Авторизация включена, но не найден $APP_DIR/clients.json." >&2
  exit 1
fi

docker compose -f deploy/docker-compose.yaml up -d --build --remove-orphans
docker compose -f deploy/docker-compose.yaml ps
