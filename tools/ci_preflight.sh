#!/bin/sh
set -eu

APP_DIR="${APP_DIR:-.}"
APP_MODULE="${APP_MODULE:-src.main:app}"

echo "[ci] APP_DIR=$APP_DIR APP_MODULE=$APP_MODULE"
python -V
pip -V

# deps + bytecode
pip install -r requirements.txt
python -m compileall -q src

# префлайты с «сухим» Telegram и отключенным воркером
export TELEGRAM_DRY=1
export PREFLIGHT=1

APP_DIR="$APP_DIR" APP_MODULE="$APP_MODULE" python tools/preflight_import.py
APP_DIR="$APP_DIR" APP_MODULE="$APP_MODULE" python tools/preflight_lifespan.py

echo "[ci] preflight OK"
