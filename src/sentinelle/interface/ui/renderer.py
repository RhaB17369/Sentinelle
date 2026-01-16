from rich.console import Console
from .layout import create_dashboard

class Renderer:
    def __init__(self):
        self.console = Console()
    
    def render_dashboard(self):
        self.console.print(create_dashboard())
        
    def clear(self):
        self.console.clear()
        
    def print_menu(self):
        self.console.print("\n[bold cyan]Select Module:[/]")
        # This could be dynamic based on registry, but keeping format for now
        from ..modules.registry import registry
        
        for i, module in enumerate(registry.get_all(), 1):
            self.console.print(f"{i}. {module.name}")
            
        self.console.print("0. Exit")
    
    def print_message(self, message: str, style: str = ""):
        self.console.print(message, style=style)
