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

class SocialEngine:
    def __init__(self, console):
        self.console = console
        self.config = bb_config
        self.config.console = console

    async def run_search(self, targets, search_type, settings):
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
                self.console.print(f"[yellow]⚠️ Failed to check for updates: {e}[/]")

        results_summary = []

        for target_val in targets:
            if search_type == "username":
                self.config.username = [target_val]
                self.config.currentUser = target_val
                self.config.currentEmail = None
                try:
                    data_list = readList("username", self.config)
                    self.config.metadata_params = readList("metadata", self.config)
                except Exception as e:
                    self.console.print(f"[red]❌ Could not load site lists: {e}[/]")
                    # Skip this target and continue with others
                    results_summary.append({
                        "target": target_val,
                        "found": 0,
                        "accounts": [],
                        "ai_analysis": None,
                        "error": str(e),
                    })
                    continue
            else:
                self.config.email = [target_val]
                self.config.currentEmail = target_val
                self.config.currentUser = None
                try:
                    data_list = readList("email", self.config)
                except Exception as e:
                    self.console.print(f"[red]❌ Could not load site lists: {e}[/]")
                    results_summary.append({
                        "target": target_val,
                        "found": 0,
                        "accounts": [],
                        "ai_analysis": None,
                        "error": str(e),
                    })
                    continue

            sites = applyFilters(data_list["sites"], self.config)
            self.config.userAgent = getRandomUserAgent(self.config)
            
            found_accounts = []
            
            # Use a callback for UI updates if provided, or handle it here
            # For now, we'll keep the UI logic in the runner or pass a progress object
            # To keep it decoupled, let's just return the results and let the caller handle UI
            # OR we can pass a progress callback.
            
            async with aiohttp.ClientSession() as session:
                semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
                
                tasks = []
                for site in sites:
                    if search_type == "username":
                        url = site["uri_check"].replace("{account}", target_val)
                        tasks.append(bb_check_site_u(site, "GET", url, session, semaphore, self.config))
                    else:
                        email_processed = processInput(target_val, site["input_operation"], self.config) if site.get("input_operation") else target_val
                        url = site["uri_check"].replace("{account}", email_processed)
                        data_post = site["data"].replace("{account}", email_processed) if site.get("data") else None
                        headers = site.get("headers")
                        tasks.append(bb_check_site_e(site, site["method"], url, session, semaphore, self.config, data_post, headers))
                
                # Progress and table tracking
                progress = settings.get("progress")
                task_id = settings.get("task_id")
                table = settings.get("table")
                log_callback = settings.get("log_callback")

                # We use a set of tasks and wait for them to complete properly
                # This is more robust than as_completed in some edge cases
                pending = {asyncio.create_task(coro) for coro in tasks}
                
                if log_callback:
                    log_callback(f"🚀 Dispatched {len(tasks)} search requests for {target_val}")

                try:
                    while pending:
                        done, pending = await asyncio.wait(
                            pending, 
                            return_when=asyncio.FIRST_COMPLETED
                        )
                        
                        for task in done:
                            try:
                                res = await task
                                if progress and task_id:
                                    progress.advance(task_id)
                                
                                if res and res.get("status") == "FOUND":
                                    found_accounts.append(res)
                                    if log_callback:
                                        log_callback(f"✅ Found: {res['name']}")
                                    if table:
                                        info = ""
                                        if res.get("metadata"):
                                            info = " | ".join([f"{m['name']}: {m['value']}" for m in res["metadata"]])
                                        table.add_row(res["name"], "[bold green][+][/]", res["url"], info)
                                elif res and res.get("status") == "ERROR":
                                    if log_callback:
                                        log_callback(f"❌ Error on: {res['name']}")
                                elif log_callback:
                                    # Still call log_callback (even if empty) to trigger UI refresh if it's tied to it
                                    # Or just call it with a dummy value that doesn't add to log but triggers update
                                    # Actually, let's just trigger the update if log_callback exists
                                    log_callback(None) 
                            except Exception as e:
                                if log_callback:
                                    log_callback(f"⚠️ Task error: {str(e)}")
                finally:
                    # Ensure all pending tasks are cancelled if we exit early
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
                    self.console.print(f"[red]❌ AI Analysis error: {e}[/]")

            # Handle Exports
            if len(found_accounts) > 0:
                if self.config.csv or self.config.pdf or self.config.json or self.config.dump:
                    createSaveDirectory(self.config)
                    if self.config.csv: saveToCsv(found_accounts, self.config)
                    if self.config.pdf: saveToPdf(found_accounts, search_type, self.config)
                    if self.config.json: saveToJson(found_accounts, self.config)
            
            results_summary.append({
                "target": target_val,
                "found": len(found_accounts),
                "accounts": found_accounts,
                "ai_analysis": self.config.ai_analysis
            })
            
            # Reset for next target
            self.config.ai_analysis = None

        return results_summary

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
