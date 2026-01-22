import asyncio
import ipaddress
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.network.geo import IPEngine

class IPTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]      IP INTELLIGENCE (OSINT)         [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        ip = input("🌐 Enter IP address: ").strip()
        if not ip:
            return

        engine = IPEngine()
        
        with self.pm.session(
            title="IP Intelligence",
            target=ip,
            total=4,
            columns=[
                ("Category", {}),
                ("Property", {"style": "dim"}),
                ("Value", {"style": "green"}),
            ]
        ) as ctx:
            # Add basic IP type info immediately
            try:
                ip_obj = ipaddress.ip_address(ip)
                pm_type = "private" if ip_obj.is_private else "public"
                ctx.add_row({"Category": "Basic", "Property": "Type", "Value": pm_type})
            except:
                pass

            engine.register_callback(self._setup_callback(ctx))
            try:
                asyncio.run(engine.run(ip))
            except Exception as e:
                ctx.log(f"[red]❌ Analysis failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, data: dict):
        # IPEngine emits dicts with Category, Property, Value
        ctx.add_row(data)
