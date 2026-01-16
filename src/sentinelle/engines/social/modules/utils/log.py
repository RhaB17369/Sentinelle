import logging
import traceback

logger = logging.getLogger(__name__)


def logError(e, message, config=None, *, include_trace=False):
    """Log an error concisely.

    - Always log the short message and exception string.
    - Only emit a full stack trace to DEBUG or when verbose is enabled or include_trace=True.
    """
    if str(e) != "":
        error = str(e)
    else:
        error = repr(e)

    logger.error(f"{message} | {error}")

    # Only include full stack trace when requested or when verbose mode is enabled
    if include_trace or (config and getattr(config, "verbose", False)):
        stacktrace = traceback.format_exc()
        logger.debug(stacktrace)

    # Print a short, user-friendly message to console if available and verbose
    if config and getattr(config, "verbose", False):
        try:
            config.console.print(f"⛔  {message}")
            config.console.print("     | An error occurred:")
            config.console.print(f"     | {error}")
        except Exception:
            # Best-effort: don't raise while logging
            pass
