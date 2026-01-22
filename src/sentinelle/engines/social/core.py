import os
import sys
import asyncio
import aiohttp
import logging
from datetime import datetime

from . import config as bb_config
from .modules.whatsmyname.list_operations import checkUpdates, readList
from .modules.utils.filter import applyFilters
from .modules.utils.userAgent import getRandomUserAgent
from .modules.utils.input import processInput
from .modules.export.file_operations import createSaveDirectory
from .modules.export.csv import saveToCsv
from .modules.export.pdf import saveToPdf
from .modules.export.json import saveToJson
from .modules.core.username import checkSite as bb_check_site_u
from .modules.core.email import checkSite as bb_check_site_e

from ...core.engine import BaseEngine, EventType

__version__ = "2.0.0"

class SocialEngine(BaseEngine):
    def __init__(self, console=None):
        super().__init__()
        self.console = console
        self.config = bb_config
        if console:
            self.config.console = console

    async def run(self, target: str, search_type: str = "username", **settings) -> Any:
        # Initialize config with settings
        self.config.dateRaw = datetime.now().strftime("%m_%d_%Y")
        self.config.datePretty = datetime.now().strftime("%B %d, %Y")
        self.config.max_concurrent_requests = settings.get("max_concurrent", 30)
        self.config.timeout = settings.get("timeout", 30)
        self.config.verbose = settings.get("verbose", False)
        self.config.ai = settings.get("ai", False)
        self.config.no_nsfw = settings.get("no_nsfw", False)
        self.config.dump = settings.get("dump", False)
        self.config.proxy = settings.get("proxy", None)
        self.config.filter = settings.get("filter", None)
        self.config.csv = settings.get("export_csv", False)
        self.config.pdf = settings.get("export_pdf", False)
        self.config.json = settings.get("export_json", False)
        self.config.instagram_session_id = os.getenv("INSTAGRAM_SESSION_ID")
        self.config.usernameFoundAccounts = []
        self.config.emailFoundAccounts = []
        self.config.no_update = settings.get("no_update", False)
        self.config.about = False
        self.config.api_url = os.getenv("API_URL", "https://ai.blackbird.run")
        self.config.ai_analysis = None

        if not self.config.no_update:
            try:
                checkUpdates(self.config)
            except Exception as e:
                self.log(f"[yellow]⚠️ Failed to check for updates: {e}[/]")

        if search_type == "username":
            self.config.username = [target]
            self.config.currentUser = target
            self.config.currentEmail = None
            try:
                data_list = readList("username", self.config)
                self.config.metadata_params = readList("metadata", self.config)
            except Exception as e:
                self.error(f"Could not load site lists: {e}")
                return None
        else:
            self.config.email = [target]
            self.config.currentEmail = target
            self.config.currentUser = None
            try:
                data_list = readList("email", self.config)
            except Exception as e:
                self.error(f"Could not load site lists: {e}")
                return None

        sites = applyFilters(data_list["sites"], self.config)
        self.config.userAgent = getRandomUserAgent(self.config)
        
        found_accounts = []
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
            
            tasks = []
            for site in sites:
                if search_type == "username":
                    url = site["uri_check"].replace("{account}", target)
                    tasks.append(bb_check_site_u(site, "GET", url, session, semaphore, self.config))
                else:
                    email_processed = processInput(target, site["input_operation"], self.config) if site.get("input_operation") else target
                    url = site["uri_check"].replace("{account}", email_processed)
                    data_post = site["data"].replace("{account}", email_processed) if site.get("data") else None
                    headers = site.get("headers")
                    tasks.append(bb_check_site_e(site, site["method"], url, session, semaphore, self.config, data_post, headers))
            
            # We use a set of tasks and wait for them to complete properly
            pending = {asyncio.create_task(coro) for coro in tasks}
            
            self.log(f"🚀 Dispatched {len(tasks)} search requests for {target}")

            try:
                while pending:
                    done, pending = await asyncio.wait(
                        pending, 
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    for task in done:
                        try:
                            res = await task
                            self.progress(advance=1)
                            
                            if res and res.get("status") == "FOUND":
                                found_accounts.append(res)
                                self.log(f"✅ Found: {res['name']}")
                                self.emit(EventType.DATA, data=res)
                            elif res and res.get("status") == "ERROR":
                                self.log(f"❌ Error on: {res['name']}")
                        except Exception as e:
                            self.log(f"⚠️ Task error: {str(e)}")
            finally:
                if pending:
                    for task in pending:
                        task.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)

        # AI Analysis
        if self.config.ai and len(found_accounts) > 2:
            try:
                from .modules.ai.client import send_prompt
                from .modules.ai.key_manager import load_api_key_from_file
                apikey = load_api_key_from_file(self.config)
                if apikey:
                    site_names = [account.get("name", "") for account in found_accounts]
                    prompt = ", ".join(site_names)
                    analysis_data = send_prompt(prompt, self.config)
                    if analysis_data:
                        self.config.ai_analysis = analysis_data
            except Exception as e:
                self.log(f"[red]❌ AI Analysis error: {e}[/]")

        # Handle Exports
        if len(found_accounts) > 0:
            if self.config.csv or self.config.pdf or self.config.json or self.config.dump:
                createSaveDirectory(self.config)
                if self.config.csv: saveToCsv(found_accounts, self.config)
                if self.config.pdf: saveToPdf(found_accounts, search_type, self.config)
                if self.config.json: saveToJson(found_accounts, self.config)
        
        result = {
            "target": target,
            "found": len(found_accounts),
            "accounts": found_accounts,
            "ai_analysis": self.config.ai_analysis
        }
        self.emit(EventType.COMPLETE, data=result)
        return result


    def setup_ai(self):
        """Configure SocialEngine AI API Key"""
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    SOCIAL ENGINE AI SETUP             [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        self.console.print("[yellow]⚠ By continuing, you acknowledge that your IP is registered for API key management.[/]")
        confirm = input("Confirm? (y/n): ").strip().lower()
        if confirm != 'y':
            return False

        try:
            from .modules.ai.key_manager import fetch_api_key_from_server
            self.config.api_url = os.getenv("API_URL", "https://ai.blackbird.run")
            return fetch_api_key_from_server(self.config)
        except Exception as e:
            self.console.print(f"[red]❌ Error setting up AI: {e}[/]")
            return False
