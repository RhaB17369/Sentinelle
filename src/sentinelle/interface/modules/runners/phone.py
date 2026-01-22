import asyncio
from typing import Any
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.network.phone_locator import PhoneTracer

class PhoneTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    PHONE INTELLIGENCE (OSINT)        [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        phone = input("📱 Enter phone number: ").strip()
        if not phone:
            return

        engine = PhoneTracer()
        
        with self.pm.session(
            title="Phone Analysis",
            target=phone,
            total=4,
            columns=[
                ("Property", {"style": "cyan", "width": 20}),
                ("Value", {"style": "green"}),
            ]
        ) as ctx:
            engine.register_callback(self._setup_callback(ctx))
            try:
                asyncio.run(engine.run(phone))
            except Exception as e:
                ctx.log(f"[red]❌ Analysis failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, result: Any):
        if result.country:
            ctx.add_row({"Property": "Country", "Value": result.country})
        if result.region:
            ctx.add_row({"Property": "Region", "Value": result.region})
        if result.carrier:
            ctx.add_row({"Property": "Carrier", "Value": result.carrier})
        if result.number_type:
            ctx.add_row({"Property": "Type", "Value": result.number_type})
        if result.gps_coordinates:
            coords = f"{result.gps_coordinates['lat']}, {result.gps_coordinates['lng']}"
            ctx.add_row({"Property": "GPS", "Value": coords})
