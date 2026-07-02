from __future__ import annotations

import re
from pathlib import Path

from app.database import get_engine_instance
from app.engines.yara_engine import DEFAULT_RULES_DIR, get_yara_config
from app.services.engine_registry import runtime_config


RULE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
ENABLED_SUFFIXES = (".yar", ".yara")
DISABLED_SUFFIX = ".disabled"


def get_rules_dir() -> Path:
    instance = get_engine_instance("yara")
    if instance is not None:
        rules_dir = Path(str(runtime_config(instance)["rules_dir"])).resolve()
    else:
        rules_dir = Path(str(get_yara_config()["rules_dir"])).resolve()
    try:
        rules_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        rules_dir = DEFAULT_RULES_DIR.resolve()
        rules_dir.mkdir(parents=True, exist_ok=True)
    return rules_dir


def list_yara_rules() -> list[dict[str, str | int | bool]]:
    rules_dir = get_rules_dir()
    rules = []
    for path in sorted(rules_dir.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file() or not is_rule_filename(path.name, allow_disabled=True):
            continue

        enabled = not path.name.endswith(DISABLED_SUFFIX)
        base_name = path.name.removesuffix(DISABLED_SUFFIX)
        stat = path.stat()
        rules.append(
            {
                "name": path.name,
                "base_name": base_name,
                "enabled": enabled,
                "size_bytes": stat.st_size,
                "modified_at": int(stat.st_mtime),
            }
        )
    return rules


def save_yara_rule(filename: str, content: bytes) -> Path:
    rule_name = normalize_rule_name(filename, allow_disabled=False)
    if not content.strip():
        raise ValueError("Rule file cannot be empty.")

    path = rule_path(rule_name)
    path.write_bytes(content)
    return path


def toggle_yara_rule(filename: str) -> Path:
    current = rule_path(normalize_rule_name(filename, allow_disabled=True))
    if not current.exists():
        raise FileNotFoundError(filename)

    if current.name.endswith(DISABLED_SUFFIX):
        target_name = current.name.removesuffix(DISABLED_SUFFIX)
    else:
        target_name = f"{current.name}{DISABLED_SUFFIX}"

    target = rule_path(normalize_rule_name(target_name, allow_disabled=True))
    current.replace(target)
    return target


def delete_yara_rule(filename: str) -> None:
    path = rule_path(normalize_rule_name(filename, allow_disabled=True))
    if not path.exists():
        raise FileNotFoundError(filename)
    path.unlink()


def rule_path(filename: str) -> Path:
    rules_dir = get_rules_dir()
    path = (rules_dir / filename).resolve()
    path.relative_to(rules_dir)
    return path


def normalize_rule_name(filename: str, allow_disabled: bool) -> str:
    name = Path(filename).name.strip()
    if not name:
        raise ValueError("Rule filename is required.")
    if not is_rule_filename(name, allow_disabled=allow_disabled):
        raise ValueError("Rule filename must end with .yar or .yara.")
    if not RULE_NAME_PATTERN.match(name):
        raise ValueError("Rule filename contains unsupported characters.")
    return name


def is_rule_filename(filename: str, allow_disabled: bool) -> bool:
    candidate = filename
    if allow_disabled and candidate.endswith(DISABLED_SUFFIX):
        candidate = candidate.removesuffix(DISABLED_SUFFIX)
    return candidate.endswith(ENABLED_SUFFIXES)
