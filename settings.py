import json
import os
import shutil
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any


SETTINGS_FILE = Path(__file__).with_name("detector_settings.json")
ENV_SETTINGS_FILE = "PII_DETECTOR_SETTINGS"

_CACHE = None


def _candidate_paths() -> list[Path]:
    return [
        Path.cwd() / "detector_settings.json",
        SETTINGS_FILE,
        Path(sys.prefix) / "pii_leak_detector" / "detector_settings.json",
    ]


def resolve_settings_path() -> Path:
    env_path = os.environ.get(ENV_SETTINGS_FILE)
    if env_path:
        path = Path(env_path).expanduser()
        if path.is_file():
            return path
        raise FileNotFoundError(f"{ENV_SETTINGS_FILE} points to missing file: {path}")
    for path in _candidate_paths():
        if path.is_file():
            return path
    searched = ", ".join(str(path) for path in _candidate_paths())
    raise FileNotFoundError(f"detector_settings.json not found. Searched: {searched}")


def active_settings_path() -> Path:
    return resolve_settings_path()


def load_settings() -> dict:
    global _CACHE
    if _CACHE is None:
        with resolve_settings_path().open("r", encoding="utf-8") as stream:
            _CACHE = json.load(stream)
    return _CACHE


def reload_settings() -> dict:
    global _CACHE
    _CACHE = None
    return load_settings()


def copy_settings_template(output_path: str = "detector_settings.json", overwrite: bool = False) -> Path:
    destination = Path(output_path).expanduser()
    if destination.exists() and not overwrite:
        raise FileExistsError(f"{destination} already exists. Use --force to overwrite it.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(resolve_settings_path(), destination)
    return destination


def get(path: str, default: Any = None) -> Any:
    value = load_settings()
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return deepcopy(default)
        value = value[part]
    return deepcopy(value)


def tuple_setting(path: str, default=()) -> tuple:
    return tuple(get(path, default))


def set_setting(path: str, default=()) -> set:
    return set(get(path, default))
