from typing import Callable, Optional, Any
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.console import Console, Group
from rich.live import Live
from rich import box


class ProgressManager:
    """Unified manager for progress + dynamic table rendering.

    Usage:
      pm = ProgressManager(console)
      pm.create(title, target, columns)
      with pm.live_panel(title):
          pm.update(...)

    The manager exposes minimal helpers so modules don't replicate Progress/Table creation.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def create(self, target_name: str, total: int, table_columns: list[tuple[str, dict]]):
        """Create the Progress and Table objects for the run."""
        progress = Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold blue]{task.fields[target]}[/]"),
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TextColumn("({task.completed}/{task.total})"),
            TextColumn("[dim]{task.description}...[/]"),
            console=self.console,
        )

        # Create a visually clear and structured table with sensible defaults
        table = Table(
            show_header=True,
            header_style="bold white",
            box=box.ROUNDED,
            expand=True,
            border_style="bright_black",
            row_styles=["", "dim"],
            show_edge=True,
            pad_edge=True,
            show_lines=True,
            highlight=True,
        )

        column_names = []
        for col, kwargs in table_columns:
            # sensible defaults for readability
            defaults = {"no_wrap": False, "overflow": "fold"}
            if "justify" not in kwargs:
                if "status" in col.lower():
                    defaults["justify"] = "center"
                elif "url" in col.lower():
                    defaults["justify"] = "left"
                else:
                    defaults["justify"] = "left"

            merged = {**defaults, **kwargs}
            table.add_column(col, **merged)
            column_names.append(col)

        # Store column order for dict-based helpers
        setattr(table, "_pm_column_names", column_names)

        task_id = progress.add_task("Processing", total=total, target=target_name)
        return progress, table, task_id

    def render_display(self, progress: Progress, table: Table, activity_log: list[str], progress_title: str = "Progress", activity_title: str = "Real-time Activity"):
        """Return a Group suitable for Live.update() with a cleaner, more professional look."""
        # Use a more compact representation for logs
        log_lines = []
        for log in activity_log[-5:]:
            log_lines.append(f"[yellow]»[/] [dim]{log}[/]")
        log_text = "\n".join(log_lines)
        
        return Group(
            # Progress bar without its own panel to avoid border stacking
            progress,
            # Single Activity panel with a cleaner border
            Panel(log_text or "[dim]Waiting for data...[/]", title=f"[bold yellow]{activity_title}[/]", border_style="bright_black", height=8),
            # Table directly in the group
            table,
        )

    def live_context(self, title: str, progress: Progress, table: Table, activity_log: list[str], refresh_per_second: int = 4, progress_title: str = "Progress", activity_title: str = "Activity"):
        """Context manager for a Live panel that contains progress, activity log and table.

        Yields the Live objeca cct so callers can call live.update(pm.render_display(...)) when they mutate progress or the activity_log.
        """
        return Live(Panel(self.render_display(progress, table, activity_log, progress_title, activity_title), title=title), console=self.console, refresh_per_second=refresh_per_second)

    def update_task(self, progress: Progress, task_id: Any, advance: int = 1, description: Optional[str] = None, completed: Optional[int] = None):
        if completed is not None:
            progress.update(task_id, description=description or progress.tasks[task_id].description, completed=completed)
        else:
            progress.update(task_id, description=description or progress.tasks[task_id].description, advance=advance)

    def add_table_row(self, table: Table, *columns, style: Optional[str] = None):
        """Add a simple row by positional columns. Optionally apply a row style."""
        if style:
            table.add_row(*columns, style=style)
        else:
            table.add_row(*columns)

    def add_table_row_by_dict(self, table: Table, row: dict, highlight: Optional[str] = None):
        """Add a row by mapping keys to column names defined at creation.

        Example: pm.add_table_row_by_dict(table, {"Site": "github", "Status": "OK", "URL": "https://..."})
        """
        colnames = getattr(table, "_pm_column_names", None)
        if not colnames:
            # No mapping available — fall back to positional behavior
            table.add_row(*[str(v) for v in row.values()])
            return

        cells = []
        for name in colnames:
            val = row.get(name, "")
            cells.append(str(val) if val is not None else "")
        table.add_row(*cells, style=highlight)

    def update_table_row(self, table: Table, key_col: str, key_value: str, new_values: dict) -> bool:
        """Find a row where the value in key_col equals key_value and update cells with new_values.

        Returns True if a row was updated, False otherwise.
        """
        colnames = getattr(table, "_pm_column_names", None)
        if not colnames:
            return False
        try:
            key_idx = colnames.index(key_col)
        except ValueError:
            return False

        columns = table.columns
        # number of data rows is the max length of column _cells
        n_rows = max((len(getattr(c, "_cells", [])) for c in columns), default=0)
        updated = False
        for i in range(n_rows):
            cell_val = ""
            if key_idx < len(columns) and i < len(getattr(columns[key_idx], "_cells", [])):
                cell_val = columns[key_idx]._cells[i]
            if str(cell_val) == str(key_value):
                # apply updates
                for k, v in new_values.items():
                    if k in colnames:
                        idx = colnames.index(k)
                        col = columns[idx]
                        cells = getattr(col, "_cells", [])
                        # ensure list is long enough
                        while len(cells) < n_rows:
                            cells.append("")
                        cells[i] = str(v)
                        col._cells = cells
                updated = True
        return updated


# Convenience singleton-like factory used by modules
_default_pm: Optional[ProgressManager] = None

def get_manager(console: Optional[Console] = None) -> ProgressManager:
    global _default_pm
    if _default_pm is None:
        _default_pm = ProgressManager(console)
    elif console is not None:
        _default_pm.console = console
    return _default_pm
