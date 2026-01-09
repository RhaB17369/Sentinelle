from rich.panel import Panel
from rich.text import Text
from rich import box
from datetime import datetime
from ...core.config import UIConfig

def create_header() -> Panel:
    """Create header panel"""
    header_text = Text()
    header_text.append(UIConfig.APP_NAME, style="bold cyan")
    header_text.append(" | ", style="white")
    header_text.append(UIConfig.APP_SUBTITLE, style="bold green")
    header_text.append(" | ", style="white")
    header_text.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="yellow")
    
    return Panel(
        header_text,
        box=box.DOUBLE,
        style=UIConfig.HEADER_STYLE,
    )
