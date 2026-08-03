#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="https://github.com/TyanRL/TimewebReverseProxy.git"
APP_DIR="${APP_DIR:-/opt/TimewebReverseProxy}"

if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo -E APP_DIR="$APP_DIR" bash "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Скрипт поддерживает Debian/Ubuntu." >&2
  exit 1
fi

apt-get update
apt-get install -y ca-certificates curl git

if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  case "$ID" in
    debian) docker_repo_os=debian ;;
    ubuntu) docker_repo_os=ubuntu ;;
    *) echo "Неподдерживаемая ОС: $ID" >&2; exit 1 ;;
  esac
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$docker_repo_os $VERSION_CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

if [[ ! -d "$APP_DIR/.git" ]]; then
  mkdir -p "$(dirname "$APP_DIR")"
  git clone "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"

if [[ ! -f .env ]]; then
  cp env.example .env
  echo "Создан $APP_DIR/.env — заполните ключи и ADMIN_TOKEN, затем повторите запуск."
  exit 0
fi

auth_enabled="$(grep -E '^[[:space:]]*AUTH_ENABLED[[:space:]]*=' .env | tail -n 1 | cut -d= -f2- | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' || true)"
if [[ "$auth_enabled" == "true" || "$auth_enabled" == "1" || "$auth_enabled" == "yes" ]] && [[ ! -f clients.json ]]; then
  printf '[\n  {"token": "monitel:change-me", "models": ["gpt-4o-mini"]}\n]\n' > clients.json
  chmod 600 clients.json
  echo "Создан $APP_DIR/clients.json — замените тестовый токен на настоящий и повторите запуск."
  exit 0
fi

./deploy/update.sh
