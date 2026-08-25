from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from app.engines.microsoft_defender import (
    DEFAULT_SCAN_TYPE,
    DEFAULT_TIMEOUT_SECONDS,
    check_microsoft_defender_health,
)
from app.workers.control_api_worker import (
    WorkerControlClient,
    agent_token,
    control_url,
    identity_payload,
)


def defender_preflight(*, platform_name: str | None = None) -> dict[str, object]:
    current_platform = os.name if platform_name is None else platform_name
    if current_platform != "nt":
        return {
            "ok": False,
            "status": "unsupported",
            "detail": "The Windows Defender agent can only run on Windows.",
        }
    config: dict[str, str | int | bool] = {
        "execution_mode": "powershell",
        "powershell_path": os.getenv(
            "MASP_MICROSOFT_DEFENDER_POWERSHELL_PATH", "powershell.exe"
        ),
        "mpcmdrun_path": os.getenv(
            "MASP_MICROSOFT_DEFENDER_MPCMDRUN_PATH", "auto"
        ),
        "default_scan_type": os.getenv(
            "MASP_MICROSOFT_DEFENDER_DEFAULT_SCAN_TYPE", DEFAULT_SCAN_TYPE
        ),
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "update_before_scan": False,
        "require_real_time_enabled": True,
    }
    result = check_microsoft_defender_health(config=config)
    return {"ok": bool(result.get("ok")), **result}


def control_preflight() -> dict[str, object]:
    local = defender_preflight()
    if not bool(local.get("ok")):
        return {"ok": False, "defender": local, "control_api": None}
    try:
        token = agent_token()
        token_path = os.getenv("MASP_WORKER_AGENT_TOKEN_FILE", "").strip()
        if token_path and not Path(token_path).is_file():
            raise RuntimeError(f"Agent token file does not exist: {token_path}")
        client = WorkerControlClient(control_url(), token)
        heartbeat = client.post_json(
            "heartbeat",
            identity_payload(process_id=os.getpid(), runtime_state="preflight"),
        )
    except Exception as exc:
        return {
            "ok": False,
            "defender": local,
            "control_api": {"ok": False, "detail": str(exc)},
        }
    return {
        "ok": True,
        "defender": local,
        "control_api": {
            "ok": True,
            "node_id": heartbeat.get("node_id") if heartbeat else None,
            "lifecycle_state": heartbeat.get("lifecycle_state") if heartbeat else None,
        },
    }


def installed_service_preflight(
    *, config_path: Path | None = None
) -> dict[str, object]:
    """Load the installed service configuration before running diagnostics."""
    try:
        from app.workers.windows_service import load_service_environment

        values = load_service_environment(config_path)
    except Exception as exc:
        return {
            "ok": False,
            "service_config": {"ok": False, "detail": str(exc)},
            "defender": None,
            "control_api": None,
        }
    result = control_preflight()
    return {
        **result,
        "service_config": {
            "ok": True,
            "node_id": values.get("MASP_WORKER_NODE_ID"),
            "control_url": values.get("MASP_WORKER_CONTROL_URL"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="MASP Windows worker diagnostics")
    parser.add_argument(
        "--control-check",
        action="store_true",
        help="Also authenticate to the Worker Control API and send a preflight heartbeat.",
    )
    parser.add_argument(
        "--service-config",
        type=Path,
        help=(
            "Load an installed worker.env file, then run the Defender and "
            "authenticated control-plane checks."
        ),
    )
    args = parser.parse_args()
    if args.service_config:
        result = installed_service_preflight(config_path=args.service_config)
    elif args.control_check:
        result = control_preflight()
    else:
        result = defender_preflight()
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    raise SystemExit(0 if bool(result.get("ok")) else 1)


if __name__ == "__main__":
    main()
