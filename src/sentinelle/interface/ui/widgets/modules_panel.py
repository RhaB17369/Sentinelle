from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.console import Group
from rich.align import Align
from ...config import UIConfig
from ...modules.registry import registry
import time


def _ascii_bar(percent: int, width: int = 40) -> str:
    filled = int((percent * width) / 100)
    return '█' * filled + '░' * (width - filled)


def create_modules_panel() -> Panel:
    """Create a dynamic modules panel with a loading bar and module status table.

    The panel probes module availability at render time (fast imports) and shows
    version / load time / progress for each discovered module.
    """
    # Initial shallow probe to populate versions quickly
    modules = registry.probe_modules()

    # Run a deeper concurrent probe in background and display a Live view while it runs
    from rich.live import Live
    import threading

    done = threading.Event()

    def run_deep_probe():
        registry.probe_modules_deep(timeout=2.0, concurrency=4)
        done.set()

    t = threading.Thread(target=run_deep_probe, daemon=True)
    t.start()

    with Live(refresh_per_second=4, vertical_overflow='ellipsis') as live:
        # keep rendering until probes complete or a sensible timeout elapses
        max_wait = 6.0
        start_time = time.perf_counter()
        while not done.is_set() and (time.perf_counter() - start_time) < max_wait:
            modules = registry.get_all()
            if modules:
                operational = sum(1 for m in modules if m.status.startswith('✓'))
                overall_pct = int((operational / len(modules)) * 100)
            else:
                overall_pct = 0

            # Header: progress bar and short status
            header = Text()
            header.append(" Loading intelligence modules... ", style="bold white on #002b36")
            header.append("\n")
            header.append("[" + _ascii_bar(overall_pct, 48) + "]")
            header.append(" ")
            header.append(
                f"{overall_pct}%",
                style=("bold green" if overall_pct == 100 else "bold yellow"),
            )

            # Table with module rows
            table = Table(show_header=True, box=box.SIMPLE)
            table.add_column("Module", style="cyan", no_wrap=True)
            table.add_column("Status", style="white", no_wrap=True)
            table.add_column("Version", style="magenta", no_wrap=True)
            table.add_column("Load Time", style="dim", no_wrap=True)
            table.add_column("Progress", style="green")

            for m in modules:
                # For LOADING, show a small progress bar instead of number
                prog_display = (
                    f"[{_ascii_bar(m.progress, 20)}] {m.progress}%"
                    if isinstance(m.progress, int)
                    else str(m.progress)
                )
                status = m.status
                # show message if present for non-ready states
                if m.message and not m.status.startswith('✓'):
                    status = f"{m.status} ({m.message})"

                table.add_row(
                    m.name,
                    status,
                    m.version or "-",
                    f"{m.load_time or '-'}s",
                    prog_display,
                )
            header_block = Align.center(Text.assemble(header, Text('\n')), vertical="top")
            panel = Panel(
                Group(header_block, table),
                title="[bold cyan]Module Loader[/]",
                border_style=UIConfig.BORDER_STYLE,
                box=UIConfig.BOX_STYLE,
                padding=(1, 1),
            )
            live.update(panel)
            time.sleep(0.25)

        # Final render after probe completes (or timeout)
        modules = registry.get_all()
        if modules:
            operational = sum(1 for m in modules if m.status.startswith('✓'))
            overall_pct = int((operational / len(modules)) * 100)
        else:
            overall_pct = 0

        header = Text()
        header.append(" Loading intelligence modules... ", style="bold white on #002b36")
        header.append("\n")
        header.append("[" + _ascii_bar(overall_pct, 48) + "]")
        header.append(" ")
        header.append(
            f"{overall_pct}%",
            style=("bold green" if overall_pct == 100 else "bold yellow"),
        )

        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Status", style="white", no_wrap=True)
        table.add_column("Version", style="magenta", no_wrap=True)
        table.add_column("Load Time", style="dim", no_wrap=True)
        table.add_column("Progress", style="green")

        for m in modules:
            prog_display = (
                f"[{_ascii_bar(m.progress, 20)}] {m.progress}%"
                if isinstance(m.progress, int)
                else str(m.progress)
            )
            status = m.status
            if m.message and not m.status.startswith('✓'):
                status = f"{m.status} ({m.message})"
            table.add_row(
                m.name,
                status,
                m.version or "-",
                f"{m.load_time or '-'}s",
                prog_display,
            )

    return Panel(
        Group(header_block, table),
        title="[bold cyan]Module Loader[/]",
        subtitle_align="left",
        border_style=UIConfig.BORDER_STYLE,
        box=UIConfig.BOX_STYLE,
        padding=(1, 1),
    )
