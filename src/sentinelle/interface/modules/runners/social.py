import asyncio
from .base import BaseTaskRunner
from ...ui.progress_manager import UIContext
from ....engines.social.core import SocialEngine

class SocialTaskRunner(BaseTaskRunner):
    def run(self):
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]      SOCIAL MEDIA SEARCH (OSINT)     [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        target = input("👤 Enter username or email: ").strip()
        if not target:
            return

        search_type = "email" if "@" in target else "username"
        engine = SocialEngine(self.console)
        
        # Determine sites count for progress bar initialization
        from ....engines.social.modules.whatsmyname.list_operations import readList
        from ....engines.social.modules.utils.filter import applyFilters
        from ....engines.social import config as bb_config
        
        try:
            data_list = readList(search_type, bb_config)
            sites = applyFilters(data_list["sites"], bb_config)
            total_sites = len(sites)
        except Exception as e:
            self.console.print(f"[red]Error loading sites: {e}[/]")
            return

        with self.pm.session(
            title="Social Search",
            target=target,
            total=total_sites,
            columns=[
                ("Site", {"style": "cyan"}),
                ("Status", {}),
                ("URL", {}),
            ]
        ) as ctx:
            engine.register_callback(self._setup_callback(ctx))
            try:
                asyncio.run(engine.run(target, search_type=search_type))
            except Exception as e:
                ctx.log(f"[red]❌ Search failed: {str(e)}[/]")
            finally:
                ctx.pause()

    def handle_data(self, ctx: UIContext, data: dict):
        ctx.add_row({
            "Site": data.get("name", "unknown"),
            "Status": "[bold green][+][/]",
            "URL": data.get("url", "")
        })
