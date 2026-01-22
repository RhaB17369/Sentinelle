import asyncio
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.network.domain_collector import DomainEngine

class DomainTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]     DOMAIN INTELLIGENCE (OSINT)      [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        domain = input("🌐 Enter domain name: ").strip()
        if not domain:
            return

        engine = DomainEngine()
        
        with self.pm.session(
            title="Domain Analysis",
            target=domain,
            total=5,
            columns=[
                ("Category", {}),
                ("Property", {"style": "dim"}),
                ("Value", {"style": "green"}),
            ]
        ) as ctx:
            engine.register_callback(self._setup_callback(ctx))
            try:
                asyncio.run(engine.run(domain))
            except Exception as e:
                ctx.log(f"[red]❌ Engine execution failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, data: dict):
        ctx.add_row(data)
