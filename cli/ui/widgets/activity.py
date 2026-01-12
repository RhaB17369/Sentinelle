from rich.panel import Panel
from rich.text import Text
from rich import box
from ...core.state import state
from ...core.config import UIConfig

def create_activity_panel() -> Panel:
    """Create activity log panel"""
    log_text = Text()
    
    # If empty, add default log
    if not state.activity_log:
        log_text.append("[System] initialized\n", style="green")
    
    for log in state.activity_log:
        time_str = log.timestamp.strftime("[%H:%M:%S] ")
        log_text.append(time_str, style="dim")
        log_text.append(f"{log.message}\n", style=log.style)
        
    return Panel(
        log_text,
        title="[bold cyan]Activity Log[/]",
        border_style=UIConfig.BORDER_STYLE,
        box=UIConfig.BOX_STYLE,
    )
