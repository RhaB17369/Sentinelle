import trio
from typing import Any
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.mail.core import MailEngine, is_email, import_submodules, get_functions

class EmailTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]  EMAIL OSINT - Sentinelle           [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        email = input("📧 Enter email address: ").strip()
        if not email or not is_email(email):
            self.console.print("[red]❌ Invalid email address[/]")
            return
        
        # Load modules
        self.console.print("[yellow]⏳ Loading modules...[/]")
        modules = import_submodules("sentinelle.engines.mail.modules")
        websites = get_functions(modules, None)
        
        engine = MailEngine(self.console)
        
        with self.pm.session(
            title="Email OSINT",
            target=email,
            total=len(websites),
            columns=[
                ("Status", {"width": 10}),
                ("Domain", {"style": "cyan"}),
                ("Information", {"style": "dim"}),
            ]
        ) as ctx:
            engine.register_callback(self._setup_callback(ctx))
            try:
                trio.run(engine.run, email, 30, 20, websites)
            except Exception as e:
                ctx.log(f"[red]❌ Scan failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, result: Any):
        domain = result.get('domain', 'unknown')
        info = ""
        if result.get('exists'):
            status = "[bold green][+][/]"
            if result.get('emailrecovery'): info += f"Recovery: {result['emailrecovery']}"
            if result.get('phoneNumber'): info += f" | Phone: {result['phoneNumber']}"
        elif result.get('rateLimit'): status = "[bold yellow][x][/]"
        elif result.get('error'): status = "[bold red][!][/]"
        else: status = "[bold magenta][-][/]"
        
        ctx.add_row({"Status": status, "Domain": domain, "Information": info})
