import time
from rich.progress import Progress, SpinnerColumn, TextColumn
from .state import state
from ..ui.renderer import Renderer
from ..modules.runner import ModuleRunner
from ..modules.registry import registry

class App:
    def __init__(self):
        self.renderer = Renderer()
        self.runner = ModuleRunner(self.renderer.console)
        
    def start(self):
        self.renderer.clear()
        self._show_loading()
        
        # Main loop
        while True:
            # Refresh logs
            if not state.activity_log:
                state.add_log("System initialized", "green")
                state.add_log("Loading APT database...", "yellow")
                state.add_log("All modules ready", "green")

            self.renderer.render_dashboard()
            self.renderer.print_menu()
            
            choice = input("\n> ")
            
            if choice == "0" or choice.lower() == "q":
                self.renderer.print_message("[yellow]Exiting SENTINNELLE...[/]")
                break
                
            choice_lower = choice.lower()
            if choice_lower == "h":
                self._show_help()
                continue
                
            module_def = None
            if choice_lower == "a":
                module_def = registry.get_by_id("apt")
            elif choice_lower == "b":
                module_def = registry.get_by_id("blockchain")
            elif choice_lower == "t":
                module_def = registry.get_by_id("traffic")
            else:
                try:
                    idx = int(choice) - 1
                    module_def = registry.get_by_index(idx)
                except ValueError:
                    pass

            if module_def:
                self._run_module(module_def)
            else:
                self.renderer.print_message("[red]Invalid choice or input[/]")
                
    def _run_module(self, module_def):
        if hasattr(self.runner, module_def.runner_method):
            method = getattr(self.runner, module_def.runner_method)
            method()
        else:
            self.renderer.print_message(f"[red]Method {module_def.runner_method} not implemented[/]")

    def _show_help(self):
        from rich.panel import Panel
        from rich.table import Table
        from rich import box
        
        table = Table(box=box.MINIMAL)
        table.add_column("Key", style="cyan")
        table.add_column("Action", style="white")
        table.add_row("1-15", "Run specific module")
        table.add_row("A", "Quick run: APT Attribution")
        table.add_row("B", "Quick run: Blockchain Intel")
        table.add_row("T", "Quick run: Traffic Analysis")
        table.add_row("H", "Show this help screen")
        table.add_row("Q", "Quit application")
        
        self.renderer.console.print(Panel(table, title="Help & Shortcuts", border_style="cyan"))
        input("\nPress Enter to continue...")
                
    def _show_loading(self):
         with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.renderer.console,
        ) as progress:
            task = progress.add_task("[cyan]Initializing SENTINNELLE...", total=100)
            for i in range(100):
                progress.update(task, advance=1)
                time.sleep(0.01)

def main():
    app = App()
    app.start()
