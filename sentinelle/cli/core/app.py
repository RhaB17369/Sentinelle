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
            
            try:
                idx = int(choice) - 1
                module_def = registry.get_by_index(idx)
                
                if module_def:
                    # Dynamically call the method on the runner
                    if hasattr(self.runner, module_def.runner_method):
                        method = getattr(self.runner, module_def.runner_method)
                        method()
                    else:
                        self.renderer.print_message(f"[red]Method {module_def.runner_method} not implemented[/]")
                else:
                    self.renderer.print_message("[red]Invalid choice[/]")
                    
            except ValueError:
                self.renderer.print_message("[red]Invalid input[/]")
                
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
