import os
import sys
import importlib
import traceback
from fastapi.testclient import TestClient # type: ignore

APP_DIR = os.getenv("APP_DIR", ".")
APP_MODULE = os.getenv("APP_MODULE", "src.main:app")
HEALTH_PATH = os.getenv("HEALTH_PATH", "/healthz")


def die(msg: str, exc: BaseException | None = None) -> None:
    print("=== PREFLIGHT LIFESPAN FAILED ===")
    print(msg)
    if exc is not None:
        traceback.print_exception(type(exc), exc, exc.__traceback__)
    sys.exit(1)


def main() -> None:
    # Явно помечаем префлайт — приложение не будет поднимать воркер
    os.environ.setdefault("PREFLIGHT", "1")

    # 1) импорт приложения
    sys.path.insert(0, os.path.abspath(APP_DIR))
    try:
        mod_name, attr = APP_MODULE.split(":", 1)
    except ValueError:
        die(f"APP_MODULE must be in format 'module:attr', got '{APP_MODULE}'")

    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        die(f"Failed to import module '{mod_name}' from APP_DIR='{APP_DIR}'", e)

    try:
        app = getattr(mod, attr)
    except AttributeError as e:
        die(f"Module '{mod_name}' has no attribute '{attr}'", e)

    print(f"[preflight] importing OK => {mod_name}:{attr}")

    # 2) запуск lifespan через TestClient
    try:
        with TestClient(app) as client:
            # 3) health-check
            r = client.get(HEALTH_PATH)
            if r.status_code != 200:
                die(f"Health check failed: GET {HEALTH_PATH} -> {r.status_code} {r.text!r}")
            print("[preflight] health check OK")
        # 4) выход из контекста — корректный shutdown
        print("[preflight] lifespan startup/shutdown OK")
    except Exception as e:
        die("Exception during lifespan run or health check", e)


if __name__ == "__main__":
    main()
