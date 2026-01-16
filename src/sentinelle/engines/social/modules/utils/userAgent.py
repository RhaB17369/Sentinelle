import random
from pathlib import Path
import importlib.resources as resources


def getRandomUserAgent(config):
    """Return a random user agent string.

    Tries these sources in order:
    1. Package resource at `sentinelle.engines/data/useragents.txt` (preferred)
    2. Relative `data/useragents.txt` based on package layout
    3. A safe default string when no file is available
    """
    # 1) Try package resource (works both in source and installed packages)
    try:
        data_path = resources.files("sentinelle.engines").joinpath("data", "useragents.txt")
        if data_path.is_file():
            text = data_path.read_text()
            userAgents = text.splitlines()
        else:
            raise FileNotFoundError
    except Exception:
        # 2) Fallback to relative path from this file
        try:
            path = Path(__file__).resolve().parents[3] / "data" / "useragents.txt"
            userAgents = path.read_text().splitlines()
        except Exception:
            # 3) Final fallback: default UA
            userAgent = "Sentinelle/2.0 (+https://github.com)"
            if getattr(config, "verbose", False) and getattr(config, "console", None):
                config.console.print(f"[yellow]⚠️ useragents.txt not found; using default UA '{userAgent}'[/]")
            return userAgent

    userAgent = random.choice(userAgents) if userAgents else "Sentinelle/2.0 (+https://github.com)"
    if getattr(config, "verbose", False) and getattr(config, "console", None):
        config.console.print(f':id: Selected random User-Agent "{userAgent}"')
    return userAgent
