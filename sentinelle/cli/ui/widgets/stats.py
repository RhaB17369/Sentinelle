from rich.panel import Panel
from rich.table import Table
from rich import box
from ...core.state import state
from ...core.config import UIConfig

def create_stats_panel() -> Panel:
    """Create statistics panel"""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan")
    table.add_column(style="green")
    
    table.add_row("Active Modules", str(state.active_modules_count))
    table.add_row("Threats Detected", str(state.threats_detected))
    table.add_row("APT Attributions", str(state.apt_attributions))
    table.add_row("Blockchain Traces", str(state.blockchain_traces))
    
    return Panel(
        table,
        title="[bold cyan]Statistics[/]",
        border_style=UIConfig.BORDER_STYLE,
        box=UIConfig.BOX_STYLE,
    )
