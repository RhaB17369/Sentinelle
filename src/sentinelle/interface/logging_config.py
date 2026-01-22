import sys
from io import StringIO
from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

class LogRedirector:
    """Context manager to temporarily redirect logs to a callback."""
    def __init__(self, callback: callable):
        self.callback = callback

    def __enter__(self):
        self._handler = logging.StreamHandler(self)
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger("sentinelle").addHandler(self._handler)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.getLogger("sentinelle").removeHandler(self._handler)

    def write(self, m):
        if m.strip():
            self.callback(m.strip())

    def flush(self):
        pass

DEFAULT_LOG_DIR = Path.home() / ".local" / "share" / "sentinelle"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "sentinelle.log"


def configure_logging(console, log_dir: Path | None = None, verbose: bool = False) -> str:
    """Configure logging for the application.

    - Adds a rotating file handler for persistent traceability
    - Adds a RichHandler that uses the provided Rich Console so logs render cleanly
    """
    if log_dir is None:
        log_dir = DEFAULT_LOG_DIR
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "sentinelle.log"

    # File handler for durable logs
    file_handler = RotatingFileHandler(str(log_file), maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    # Rich handler for console output (integrates with the app's Console)
    # Hide time and level to keep the UI clean; keep tracebacks disabled by default
    rich_handler = RichHandler(console=console, show_time=False, show_level=False, show_path=False, rich_tracebacks=False)
    rich_handler.setLevel(logging.INFO if not verbose else logging.DEBUG)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Quiet down high-frequency library logs that interfere with Rich Live UI
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("trio").setLevel(logging.WARNING)

    # Avoid adding duplicate handlers on reconfigure
    if not any(isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", None) == str(log_file) for h in root_logger.handlers):
        root_logger.addHandler(file_handler)

    if not any(isinstance(h, RichHandler) for h in root_logger.handlers):
        root_logger.addHandler(rich_handler)

    # Sanitize existing log file from obvious test/demo lines to keep history clean
    try:
        sanitize_log_file(log_file)
    except Exception:
        # Best-effort; do not fail the startup if sanitize fails
        logging.getLogger("sentinelle").debug("Failed to sanitize log file on startup", exc_info=False)

    return str(log_file)


def sanitize_log_file(log_file_path: str | Path | None = None, patterns: list | None = None):
    """Remove known test/demo lines from the log file to keep the history clean.

    This is a destructive operation (rewrites the file) but it's safe for obvious test markers.
    """
    if patterns is None:
        patterns = ["simulated", "demo", "smoke test"]

    if log_file_path is None:
        log_file_path = DEFAULT_LOG_FILE
    log_file_path = Path(log_file_path)

    if not log_file_path.exists():
        return

    with open(log_file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    cleaned = [l for l in lines if not any(p.lower() in l.lower() for p in patterns)]

    # Only rewrite if something changed
    if len(cleaned) != len(lines):
        with open(log_file_path, "w", encoding="utf-8") as f:
            f.writelines(cleaned)


def ui_event(message: str, state_obj=None, style: str = "green", level: int = logging.INFO):
    """Emit a user-visible event:

    - Log the message to the persistent logger
    - Add a short entry into `state.activity_log` for live UI visibility
    """
    logger = logging.getLogger("sentinelle")
    try:
        logger.log(level, message)
    except Exception:
        # Best-effort: don't fail if logging is misconfigured
        pass

    if state_obj is None:
        try:
            from .state import state as _state
            state_obj = _state
        except Exception:
            state_obj = None

    if state_obj:
        try:
            state_obj.add_log(message, style)
        except Exception:
            logger.debug("Failed to add UI event to state", exc_info=False)


def tail_log_to_state(log_file_path: str | Path | None = None, state=None, num_lines: int = 10):
    """Load last `num_lines` from `log_file_path` into the app `state.activity_log` for display.

    This gives users quick traceability in the UI without inventing static placeholder messages.
    """
    if state is None:
        return

    if log_file_path is None:
        log_file_path = DEFAULT_LOG_FILE
    else:
        log_file_path = Path(log_file_path)

    try:
        if not log_file_path.exists():
            return

        with open(log_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        last_lines = lines[-num_lines:]
        for line in last_lines:
            # Log file format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            # We only want to show the message portion in the UI (no timestamps or long logger names)
            try:
                parts = line.strip().split(" - ")
                if len(parts) >= 4:
                    message = parts[-1]
                elif len(parts) >= 2:
                    # Fallback: maybe not the full formatter, take last part
                    message = parts[-1]
                else:
                    message = line.strip()

                # Remove testing/demo markers to avoid showing artificial entries
                if message.lower().startswith("simulated "):
                    message = message[len("simulated "):].strip()

                state.add_log(message, style="white")
            except Exception:
                # Fallback to raw line if parsing fails
                state.add_log(line.strip(), style="white")
    except Exception:
        logging.getLogger("sentinelle").exception("Failed to read log file for state tailing")
