from typing import Callable, Optional, Any, List, Dict, Union
from datetime import datetime
import re
import threading
import sys
import io
import warnings
import logging
import os
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.rule import Rule
from rich.layout import Layout
from rich.tree import Tree
from rich import box

# Military-grade UI synchronization
_ui_lock = threading.Lock()

class FDRedirector:
    """Rigorous FD-level redirection to capture C-level and subprocess output."""
    def __init__(self, log_func):
        self.log_func = log_func
        self.pipe_out, self.pipe_in = os.pipe()
        # Set pipe_out to non-blocking
        import fcntl
        flags = fcntl.fcntl(self.pipe_out, fcntl.F_GETFL)
        fcntl.fcntl(self.pipe_out, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        
        self.original_stdout_fd = os.dup(sys.stdout.fileno())
        self.original_stderr_fd = os.dup(sys.stderr.fileno())
        self.thread = threading.Thread(target=self._read_pipe, daemon=True)
        self.running = False

    def start(self):
        self.running = True
        os.dup2(self.pipe_in, sys.stdout.fileno())
        os.dup2(self.pipe_in, sys.stderr.fileno())
        self.thread.start()

    def stop(self):
        self.running = False
        os.dup2(self.original_stdout_fd, sys.stdout.fileno())
        os.dup2(self.original_stderr_fd, sys.stderr.fileno())
        os.close(self.pipe_in)
        os.close(self.original_stdout_fd)
        os.close(self.original_stderr_fd)

    def _read_pipe(self):
        import select
        while self.running:
            try:
                r, _, _ = select.select([self.pipe_out], [], [], 0.1)
                if r:
                    data = os.read(self.pipe_out, 4096)
                    if not data: break
                    for line in data.decode('utf-8', errors='ignore').splitlines():
                        if line.strip():
                            self.log_func(line.strip())
            except (Exception, OSError):
                break
        os.close(self.pipe_out)

class LogHandler(logging.Handler):
    def __init__(self, log_func):
        super().__init__()
        self.log_func = log_func
    def emit(self, record):
        try:
            msg = self.format(record)
            self.log_func(msg)
        except Exception:
            pass

class UIContext:
    """A context-managed UI session for a specific task.
    
    Handles the Live display, progress, table, and activity logs.
    """
    def __init__(self, console: Console, title: str, total: int, target: str, columns: List[tuple], refresh_per_second: int = 10):
        self.console = console
        self.title = title
        self.activity_log: List[str] = []
        self.refresh_per_second = refresh_per_second
        
        # 1. Create Progress
        self.progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold blue]{task.fields[target]}[/]"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("({task.completed}/{task.total})"),
            TextColumn("[dim]{task.description}...[/]"),
            console=self.console,
        )
        self.task_id = self.progress.add_task("Processing", total=total, target=target)
        
        # 2. Create Table
        self.table = Table(
            show_header=True,
            header_style="bold white",
            box=box.ROUNDED,
            expand=True,
            border_style="bright_black",
            row_styles=["", "dim"],
            show_edge=True,
            show_lines=True,
        )
        self.column_names = []
        for col, kwargs in columns:
            self.table.add_column(col, **kwargs)
            self.column_names.append(col)

        self.consultation_mode = False
        self._live: Optional[Live] = None
        self._fd_redirector: Optional[FDRedirector] = None
        self._log_handler: Optional[LogHandler] = None
        self._stdout = None
        self._stderr = None
        self._layout = Layout()
        self._setup_layout()

    def _setup_layout(self):
        """Partition the screen for absolute control."""
        self._layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="nav", size=3),
            Layout(name="footer", size=3),
        )
        self._layout["main"].split_row(
            Layout(name="logs", ratio=1),
            Layout(name="results", ratio=2),
        )

    def __enter__(self):
        with _ui_lock:
            # Absolute warning suppression
            warnings.filterwarnings("ignore")
            
            # Save original stream objects before redirection
            self._stdout = sys.stdout
            self._stderr = sys.stderr
            
            # Redirect logging
            self._log_handler = LogHandler(self.log)
            logging.getLogger().addHandler(self._log_handler)
            
            # Force close any existing active context
            manager = get_manager()
            if manager._active_context and manager._active_context._live:
                try:
                    manager._active_context._live.stop()
                except:
                    pass
            
            manager._active_context = self
            
            # 1. Capture original stdout/stderr FDs to protect them for Live
            real_stdout_fd = os.dup(sys.stdout.fileno())
            
            # 2. Start FD-level redirection (redirects FD 1 and 2 to logs)
            self._fd_redirector = FDRedirector(self.log)
            self._fd_redirector.start()

            # 3. Create a dedicated console for Live using the protected FD copy
            # Use the original raw stream to ensure ANSI sequences work
            self._live_console = Console(file=os.fdopen(real_stdout_fd, 'w'), force_terminal=True)

            self._live = Live(
                self._layout,
                console=self._live_console,
                refresh_per_second=self.refresh_per_second,
                screen=True,  # Alternate Buffer: The nuclear option
                auto_refresh=True,
            )
            self._live.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with _ui_lock:
            if self._live:
                self._live.stop()

            # Stop FD redirection and restore original streams
            if self._fd_redirector:
                self._fd_redirector.stop()

            # Restore logging
            if self._log_handler:
                logging.getLogger().removeHandler(self._log_handler)
            
            if get_manager()._active_context == self:
                get_manager()._active_context = None

    def _render_layout(self):
        """Update the layout components with current state."""
        from rich.text import Text
        
        # Header
        self._layout["header"].update(Rule(f"[bold cyan] SENTINELLE INTELLIGENCE: {self.title} [/]", style="cyan"))
        
        # Navigation Bar (Dedicated to scrolling)
        nav_text = Text()
        nav_text.append("Commands: ", style="bold white")
        nav_text.append("[↑/↓] Scroll ", style="cyan")
        nav_text.append("[PgUp/PgDn] Page ", style="cyan")
        nav_text.append("[Home/End] Top/Bottom ", style="cyan")
        nav_text.append("[Enter] Continue ", style="cyan")
        nav_text.append("[H]elp ", style="cyan")
        nav_text.append("[?]Tips", style="bright_black")
        self._layout["nav"].update(Panel(nav_text, border_style="bright_black"))

        # Footer / Progress
        if not self.consultation_mode:
            self._layout["footer"].update(Panel(self.progress, border_style="cyan"))
        else:
            self._layout["footer"].update(Panel(
                "[bold blink green] CONSULTATION MODE [/] - [white]Intelligence gathered. Press Enter to commit and exit...[/]", 
                border_style="green",
                padding=(0, 1)
            ))
        
        # Logs
        log_lines = []
        for log in self.activity_log[-15:]:  # More logs in alternate screen
            log_lines.append(f"[yellow]»[/] {log}")
        log_text = "\n".join(log_lines) or "[dim]Waiting for intelligence...[/]"
        self._layout["logs"].update(Panel(log_text, title="[bold yellow]ACTIVITY[/]", border_style="bright_black"))
        
        # Results Table
        self._layout["results"].update(self.table)

    def log(self, message: str):
        """Add a timestamped log message and update layout."""
        if not message: return
        clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', str(message)).strip()
        if not clean_msg: return
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.activity_log.append(f"[[dim]{timestamp}[/]] {clean_msg}")
        if len(self.activity_log) > 100: 
            self.activity_log.pop(0)
            
        self._render_layout()
        
        # Also sync to global app state
        try:
            from ..state import state
            state.add_log(clean_msg, "white")
        except:
            pass

    def update_progress(self, advance: int = 1, completed: Optional[int] = None, total: Optional[int] = None, description: Optional[str] = None, **kwargs):
        """Bulletproof progress update and layout refresh."""
        update_data = {}
        if description is not None: update_data["description"] = description
        if completed is not None: update_data["completed"] = completed
        if total is not None: update_data["total"] = total
        
        if advance is not None and completed is None and total is None:
            update_data["advance"] = advance
            
        for k in ['advance', 'completed', 'total', 'description']:
            if k in kwargs and k not in update_data:
                update_data[k] = kwargs[k]

        try:
            self.progress.update(self.task_id, **update_data)
            self._render_layout()
        except Exception:
            pass

    def add_row(self, data: Dict[str, Any], style: Optional[str] = None):
        cells = []
        for name in self.column_names:
            val = data.get(name, "")
            cells.append(str(val))
        self.table.add_row(*cells, style=style)
        self._render_layout()

    def refresh(self):
        """Force a layout update."""
        self._render_layout()


    def pause(self):
        """Transition to static consultation mode and wait for user acknowledgment."""
        if self._live:
            # Update footer to consultation mode
            self.consultation_mode = True
            self._render_layout()
            
            # Use original stdin for the blocking call to avoid any redirection issues
            try:
                # We stay in the alternate buffer during the wait
                input()
            except EOFError:
                pass
            
            # Stop Live (this switches back to main buffer)
            self._live.stop()
            self._live = None

        # Absolute Persistence: Print the final table and a summary to the permanent STDOUT
        self._stdout.write("\n")
        persistent_console = Console(file=self._stdout)
        persistent_console.print(Rule(f"[bold cyan] FINAL REPORT: {self.title} [/]", style="cyan"))
        persistent_console.print(self.table)
        persistent_console.print(f"[dim]Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]\n")



class ProgressManager:
    """Unified manager for UI tasks."""
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self._active_context: Optional[UIContext] = None

    def session(self, title: str, target: str, total: int, columns: List[tuple], refresh_per_second: int = 10) -> UIContext:
        """Create a new UI session context."""
        return UIContext(self.console, title, total, target, columns, refresh_per_second)

    def create(self, target_name: str, total: int, table_columns: List[tuple]):
        """Legacy / Compatibility method for raw progress/table access."""
        ctx = self.session("Legacy", target_name, total, table_columns)
        
        class TableProxy:
            def __init__(self, table, context):
                self.table = table
                self.context = context
            def add_row(self, *args, **kwargs):
                if args:
                    self.table.add_row(*args, **kwargs)
                elif "data" in kwargs:
                    self.context.add_row(kwargs["data"])
                self.context.refresh()
            def __getattr__(self, name):
                return getattr(self.table, name)

        return ctx.progress, TableProxy(ctx.table, ctx), ctx.task_id


# Singleton instance with global scope
_instance: Optional[ProgressManager] = None

def get_manager(console: Optional[Console] = None) -> ProgressManager:
    global _instance
    if _instance is None:
        _instance = ProgressManager(console)
    elif console is not None:
        _instance.console = console
    return _instance