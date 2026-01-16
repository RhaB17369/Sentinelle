from rich.panel import Panel
from rich.table import Table
from rich import box
from ...config import UIConfig
from ...modules.registry import registry

def create_modules_panel() -> Panel:
    """Create modules panel"""
    table = Table(show_header=True, box=box.SIMPLE)
    table.add_column("Module", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Level", style="yellow")
    
    for module in registry.get_all():
        table.add_row(module.name, module.status, module.level)
    
    return Panel(
        table,
        title="[bold cyan]Advanced Modules[/]",
        border_style=UIConfig.BORDER_STYLE,
        box=UIConfig.BOX_STYLE,
    )
