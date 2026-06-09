"""Dynamic plugin loader for modules/ directory."""

import importlib.util
import logging
from pathlib import Path
from typing import Any, List

MODULES_DIR = Path("modules")
_loaded = {}


def load_all_plugins(engine=None) -> List[str]:
    if not MODULES_DIR.exists():
        MODULES_DIR.mkdir(exist_ok=True)
        return []
    loaded = []
    for p in sorted(MODULES_DIR.glob("*.py")):
        if p.name == "__init__.py":
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"modules.{p.stem}", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "register"):
                mod.register(engine)
            _loaded[p.stem] = mod
            loaded.append(p.stem)
            logging.info("[Plugin] Loaded %s", p.name)
        except Exception:
            logging.exception("[Plugin] Failed %s", p)
    return loaded
