from __future__ import annotations

import contextlib
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import sys
import threading

from app.workers.control_api_worker import run_forever


SERVICE_NAME = "MASPWorker"
SERVICE_DISPLAY_NAME = "MASP Malware Scan Worker"
CONFIG_FILENAME = "worker.env"
SAFE_ENV_NAME = re.compile(r"^MASP_[A-Z0-9_]+$")

try:  # Imported only on Windows agent installations.
    import servicemanager  # type: ignore[import-not-found]
    import win32service  # type: ignore[import-not-found]
    import win32serviceutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - Linux CI exercises helpers, not SCM.
    servicemanager = None
    win32service = None
    win32serviceutil = None


def program_data_dir() -> Path:
    return Path(os.getenv("ProgramData", r"C:\ProgramData")) / "MASP" / "Worker"


def default_config_path() -> Path:
    return program_data_dir() / CONFIG_FILENAME


def parse_config_file(path: Path) -> dict[str, str]:
    """Read the administrator-owned, line-oriented MASP service config."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Unable to read Windows worker config {path}: {exc}") from exc
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not SAFE_ENV_NAME.fullmatch(key):
            raise RuntimeError(
                f"Invalid config entry on line {line_number}; expected MASP_NAME=value."
            )
        if key == "MASP_DATABASE_URL":
            raise RuntimeError("Windows control workers must not receive MASP_DATABASE_URL.")
        values[key] = value.strip()
    return values


def load_service_environment(path: Path | None = None) -> dict[str, str]:
    values = parse_config_file(path or default_config_path())
    values["MASP_WORKER_TRANSPORT"] = "control_api"
    required = {
        "MASP_WORKER_CONTROL_URL",
        "MASP_WORKER_AGENT_TOKEN_FILE",
        "MASP_WORKER_NODE_ID",
    }
    missing = sorted(key for key in required if not values.get(key, "").strip())
    if missing:
        raise RuntimeError(f"Windows worker config is missing: {', '.join(missing)}")
    token_path = Path(values["MASP_WORKER_AGENT_TOKEN_FILE"])
    if not token_path.is_file():
        raise RuntimeError(f"Worker agent token file does not exist: {token_path}")
    os.environ.update(values)
    os.environ.pop("MASP_DATABASE_URL", None)
    return values


def configure_service_logging() -> logging.Logger:
    log_dir = program_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("masp.windows_worker")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            log_dir / "worker.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
    return logger


class _LoggerStream:
    def __init__(self, logger: logging.Logger, level: int):
        self.logger = logger
        self.level = level
        self.buffer = ""

    def write(self, value: str) -> int:
        self.buffer += value
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if line.strip():
                self.logger.log(self.level, line.rstrip())
        return len(value)

    def flush(self) -> None:
        if self.buffer.strip():
            self.logger.log(self.level, self.buffer.rstrip())
        self.buffer = ""


if win32serviceutil is not None:

    class MaspWorkerService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = (
            "Executes assigned malware scan engines through the authenticated "
            "MASP Worker Control API."
        )

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()

        def SvcDoRun(self) -> None:
            logger = configure_service_logging()
            try:
                load_service_environment()
                servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} started")
                with contextlib.redirect_stdout(
                    _LoggerStream(logger, logging.INFO)
                ), contextlib.redirect_stderr(_LoggerStream(logger, logging.ERROR)):
                    run_forever(stop_event=self.stop_event)
            except Exception:
                logger.exception("MASP Windows worker stopped unexpectedly")
                servicemanager.LogErrorMsg(
                    f"{SERVICE_DISPLAY_NAME} stopped unexpectedly; see worker.log"
                )
                raise
            finally:
                servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")

else:
    MaspWorkerService = None  # type: ignore[assignment,misc]


def main() -> None:
    if os.name != "nt" or win32serviceutil is None or MaspWorkerService is None:
        raise SystemExit(
            "The MASP Windows service host requires Windows and pywin32."
        )
    # ``python -m`` otherwise records ``windows_service.Class`` in the SCM,
    # which is not importable from the package root when PythonService.exe
    # starts in System32.
    MaspWorkerService.__module__ = "app.workers.windows_service"
    win32serviceutil.HandleCommandLine(MaspWorkerService)


if __name__ == "__main__":
    main()
