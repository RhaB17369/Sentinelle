import os
import time
from pathlib import Path

# Import and load environment variables from .env file
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path, override=False)
except ImportError:
    # If python-dotenv is not installed, manually load .env
    env_path = Path(__file__).parent.parent.parent.parent / '.env'
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"\'')

from rich.progress import Progress, SpinnerColumn, TextColumn
from .state import state
from .ui.renderer import Renderer
from .modules.runner import ModuleRunner
from .modules.registry import registry
from .logging_config import configure_logging, tail_log_to_state


class App:
    def __init__(self):
        self.renderer = Renderer()
        # Configure logging (file + Rich console) and populate initial activity logs
        log_file = configure_logging(self.renderer.console)
        tail_log_to_state(log_file, state)
        # Record app start in permanent logs
        import logging as _logging
        _logging.getLogger("sentinelle").info("Application initialized")

        self.runner = ModuleRunner(self.renderer.console)

    def start(self):
        self.renderer.clear()
        self._show_loading()

        # Check and warn about missing API keys
        self._check_api_keys()

        # Main loop
        while True:
            # Refresh logs: if no activity logs are present, populate them from the log file for traceability
            if not state.activity_log:
                tail_log_to_state()

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

            if choice_lower == "r":
                # Refresh module discovery and statuses
                registry.discover()
                registry.probe_modules()
                self.renderer.print_message("[green]Modules refreshed.[/]")
                continue

            if choice_lower == "m":
                # Show modules with indexes and allow selection
                self.renderer.console.print("\n[bold cyan]Available Modules:[/]")
                for i, module in enumerate(registry.get_all(), 1):
                    self.renderer.console.print(
                        f"{i}. {module.name} [{module.status}] v{module.version or '-'} "
                        f"({module.load_time or '-'}s)"
                    )
                sel = input("\nSelect module number to run (or Enter to cancel): ").strip()
                if sel:
                    try:
                        idx = int(sel) - 1
                        module_def = registry.get_by_index(idx)
                        if module_def:
                            self._run_module(module_def)
                        else:
                            self.renderer.print_message("[red]Invalid module index[/]")
                    except ValueError:
                        self.renderer.print_message("[red]Invalid selection[/]")
                continue

            if choice_lower == "s":
                self.renderer.print_message("[dim]Use the module menu (M) or number keys to start modules.[/]")
                continue

            module_def = None
            if choice_lower == "e":
                module_def = registry.get_by_id("email")
            elif choice_lower == "p":
                module_def = registry.get_by_id("phone")
            elif choice_lower == "i":
                module_def = registry.get_by_id("ip")
            elif choice_lower == "s":
                module_def = registry.get_by_id("social")
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
            try:
                method()
            except KeyboardInterrupt:
                self.renderer.console.print("\n[yellow]⚠ Process interrupted by user.[/]")
            except Exception as e:
                self.renderer.console.print(f"\n[red]❌ Unexpected error: {str(e)}[/]")
                import logging
                logging.getLogger("sentinelle").error(f"Error running {module_def.name}: {e}", exc_info=True)
        else:
            self.renderer.print_message(f"[red]Method {module_def.runner_method} not implemented[/]")

    def _show_help(self):
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        table = Table(box=box.MINIMAL)
        table.add_column("Key", style="cyan")
        table.add_column("Action", style="white")
        table.add_row("1..N", "Select module by number")
        table.add_row("E", "Quick run: Email OSINT (if available)")
        table.add_row("P", "Quick run: Phone Intelligence (if available)")
        table.add_row("I", "Quick run: IP Intelligence (if available)")
        table.add_row("M", "Open Modules menu")
        table.add_row("R", "Refresh module discovery/status")
        table.add_row("H", "Show this help screen")
        table.add_row("Q", "Quit application")

        self.renderer.console.print(Panel(table, title="Help & Shortcuts", border_style="cyan"))

        input("\nPress Enter to continue...")

    def _check_api_keys(self):
        """Check for required API keys and warn if missing"""
        missing_keys = []
        if not os.getenv('OPENCAGE_API_KEY'):
            missing_keys.append('OPENCAGE_API_KEY (Phone Intelligence GPS)')

        if missing_keys:
            self.renderer.print_message("\n[yellow]⚠️  Missing API Keys:[/]")
            for key in missing_keys:
                self.renderer.print_message(f"  • {key}")
            self.renderer.print_message("[dim]Set them in .env file or environment variables[/]\n")
            input("Press Enter to continue...")

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
