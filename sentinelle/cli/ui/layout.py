from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from .widgets.header import create_header
from .widgets.stats import create_stats_panel
from .widgets.modules_panel import create_modules_panel
from .widgets.activity import create_activity_panel

def create_dashboard() -> Layout:
    """Create main dashboard layout"""
    layout = Layout()
    
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    
    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )
    
    layout["left"].split_column(
        Layout(name="stats", size=8),
        Layout(name="activity"),
    )
    
    # Add content
    layout["header"].update(create_header())
    layout["stats"].update(create_stats_panel())
    layout["right"].update(create_modules_panel())
    layout["activity"].update(create_activity_panel())
    
    footer_text = Text()
    footer_text.append("Commands: ", style="bold white")
    footer_text.append("[Q]uit ", style="cyan")
    footer_text.append("[A]PT ", style="cyan")
    footer_text.append("[B]lockchain ", style="cyan")
    footer_text.append("[T]raffic ", style="cyan")
    footer_text.append("[H]elp", style="cyan")
    
    layout["footer"].update(Panel(footer_text, style="white on blue"))
    
    return layout
