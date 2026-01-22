import asyncio
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.network.latency_tracer import LatencyTracer

class NetworkTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]      NETWORK SIGINT ANALYSIS         [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        target = input("🌐 Enter IP or Hostname: ").strip()
        if not target:
            return

        engine = LatencyTracer()
        
        with self.pm.session(
            title="Network SIGINT",
            target=target,
            total=6,
            columns=[
                ("Category", {}),
                ("Property", {"style": "dim"}),
                ("Value", {"style": "green"}),
            ]
        ) as ctx:
            engine.register_callback(self._setup_callback(ctx))
            try:
                asyncio.run(engine.run(target))
            except Exception as e:
                ctx.log(f"[red]❌ SIGINT Analysis failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, data: dict):
        ctx.add_row(data)
