# tools/preflight_import.py
import os, sys, importlib, traceback
APP_DIR = os.getenv("APP_DIR", "src")
APP_MODULE = os.getenv("APP_MODULE", "main:app")  # формат module:attr, напр. main:app

sys.path.insert(0, os.path.abspath(APP_DIR))
print("[preflight] cwd:", os.getcwd())
print("[preflight] sys.path[0]:", sys.path[0])

try:
    mod_name, attr = APP_MODULE.split(":", 1)
    mod = importlib.import_module(mod_name)
    print("[preflight] imported:", mod.__name__, "from", getattr(mod, "__file__", "?"))
    app = getattr(mod, attr)
    print("[preflight] OK:", attr, type(app))
except Exception:
    print("=== PREFLIGHT FAILED ===")
    traceback.print_exc()
    raise SystemExit(1)
