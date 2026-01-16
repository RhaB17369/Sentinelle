import time
import os
import sys
import re
import logging
import asyncio
from datetime import datetime
from io import StringIO
from rich.console import Console, Group
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from ..state import state
from ..logging_config import ui_event
from ..ui.progress_manager import get_manager

# Import SocialEngine
try:
    from ...engines.social.core import SocialEngine
    SOCIAL_ENGINE_AVAILABLE = True
    SOCIAL_ENGINE_ERROR = None
except Exception as e:
    SOCIAL_ENGINE_AVAILABLE = False
    SOCIAL_ENGINE_ERROR = str(e)

# Import MailEngine (Native Engine)
try:
    from ...engines.mail.core import (
        is_email, 
        print_result as email_print_result,
        import_submodules,
        get_functions,
        launch_module,
        maincore as email_maincore
    )
    from ...engines.mail import core as email_core
    EMAIL_OSINT_AVAILABLE = True
    EMAIL_OSINT_ERROR = None
except Exception as e:
    # Capture any import problem (missing dependencies, etc.) and expose the error
    EMAIL_OSINT_AVAILABLE = False
    EMAIL_OSINT_ERROR = str(e)
    email_core = None

# Async support
try:
    import trio
    import httpx
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False


class LogRedirector:
    """Intercepts stdout/stderr and redirects it to a callback (e.g., activity log)"""
    def __init__(self, callback):
        self.callback = callback
        self._stdout = sys.stdout
        self._stderr = sys.stderr

    def write(self, message):
        if message.strip():
            self.callback(message.strip())

    def flush(self):
        pass

    def __enter__(self):
        sys.stdout = self
        sys.stderr = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._stdout
        sys.stderr = self._stderr


class ModuleRunner:
    """Minimal runner with only 3 real modules: Email OSINT, Phone Intelligence, IP Intelligence"""
    
    def __init__(self, console: Console):
        self.console = console
        self.logger = logging.getLogger(__name__)

        # Log availability of optional engines for traceability
        try:
            self.logger.info("SocialEngine available: %s", bool(SOCIAL_ENGINE_AVAILABLE))
            self.logger.info("Email OSINT available: %s", bool(EMAIL_OSINT_AVAILABLE))
        except Exception:
            # Never crash the UI if logging fails
            pass
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 1: EMAIL OSINT (Holehe v1.61 via engine_mail_collector)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_email_osint(self):
        """Email OSINT with real-time dynamic table and progress bar"""
        if not EMAIL_OSINT_AVAILABLE:
            msg = "Email OSINT module not available"
            if 'EMAIL_OSINT_ERROR' in globals() and EMAIL_OSINT_ERROR:
                msg += f": {EMAIL_OSINT_ERROR}"
            self.console.print(f"[red]❌ {msg}[/]")
            self.console.print("[yellow]💡 Tip: install missing dependencies: pip install beautifulsoup4 termcolor[/]")
            self.logger.warning("Attempted to run Email OSINT but module is not available: %s", EMAIL_OSINT_ERROR)
            self._pause()
            return
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]  EMAIL OSINT - Holehe v1.61           [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        email = input("📧 Enter email address: ").strip()
        if not email or not is_email(email):
            self.console.print("[red]❌ Invalid email address[/]")
            self._pause()
            return
        
        self.logger.info("Starting Email OSINT scan for: %s", email)
        ui_event(f"Started Email OSINT scan: {email}", state, style="cyan")

        # Setup Dynamic UI components via ProgressManager
        pm = get_manager(self.console)
        
        # Get websites count for progress
        from ...engines.mail.core import MailEngine, import_submodules, get_functions
        modules = import_submodules("sentinelle.engines.mail.modules")
        websites = get_functions(modules, None)
        
        progress, table, scan_task = pm.create(
            target_name=email,
            total=len(websites),
            table_columns=[
                ("Status", {"width": 10}),
                ("Domain", {"style": "cyan"}),
                ("Information", {"style": "dim"})
            ]
        )
        
        # Results storage for final report
        all_results = []
        start_time = time.time()
        
        # Real-time activity log
        activity_log = []
        def add_activity(msg):
            # Clean up message (remove ANSI codes if any)
            clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', str(msg))
            activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {clean_msg}")
            if len(activity_log) > 5:
                activity_log.pop(0)

        def update_ui(result):
            all_results.append(result)
            domain = result.get('domain', 'unknown')
            info = ""
            
            # Extract status with better robustness
            exists = result.get('exists', False)
            rate_limit = result.get('rateLimit', False)
            error = result.get('error', False)
            
            if exists:
                status = "[bold green][+][/]"
                if result.get('emailrecovery'): info += f"Recovery: {result['emailrecovery']}"
                if result.get('phoneNumber'): info += f" | Phone: {result['phoneNumber']}"
            elif rate_limit:
                status = "[bold yellow][x][/]"
            elif error:
                status = "[bold red][!][/]"
            else:
                # For non-matches, we don't add to the dynamic table to avoid clutter
                # But we still keep them in all_results for the final summary if needed
                return
            
            pm.add_table_row(table, status, domain, info)

        try:
            engine = MailEngine(self.console)
            self.console.print(f"\n[yellow]⏳ Starting live scan for {email}...[/]\n")
            
            # Setup Live display with a bypass console to avoid LogRedirector recursion
            # Force terminal mode to prevent scrolling panel issues
            original_stdout = sys.stdout
            live_console = Console(file=original_stdout, force_terminal=True)
            
            try:
                # Use pm.render_display for consistent layout. No title/border on Live itself.
                with Live(pm.render_display(progress, table, activity_log), console=live_console, refresh_per_second=4, screen=False) as live:
                    def live_activity(msg):
                        if msg:
                            add_activity(msg)
                        live.update(pm.render_display(progress, table, activity_log))

                    with LogRedirector(live_activity):
                        # Run scan
                        all_results = trio.run(
                            engine.run_search, 
                            email, 
                            lambda r: (update_ui(r), pm.update_task(progress, scan_task), live.update(pm.render_display(progress, table, activity_log))),
                            30,
                            live_activity
                        )
            except KeyboardInterrupt:
                self.console.print("\n[yellow]⚠️ Scan interrupted by user. Returning to menu...[/]")
                ui_event("Email OSINT scan interrupted", state, style="yellow")
                return # Stop execution and don't show summary
                
        except Exception as e:
            self.console.print(f"[red]❌ Error: {str(e)}[/]")

        if all_results:
            self._display_email_results(email, all_results, start_time)
            state.add_log(f"✓ Email OSINT completed: {email}")
            self.logger.info("Email OSINT completed for %s (%d results)", email, len(all_results))
            ui_event(f"Email OSINT completed: {email} ({len(all_results)} results)", state, style="green")
        
        self._pause()

    def _display_email_results(self, email: str, results: list, start_time: float):
        """Display email OSINT summary and credits (list is already shown in dynamic table)"""
        
        # Legend
        self.console.print(f"\n[bold green][+] Email used[/], [bold magenta][-] Email not used[/], [bold yellow][x] Rate limit[/], [bold red][!] Error[/]")
        
        # Summary
        elapsed = round(time.time() - start_time, 2)
        self.console.print(f"\n[bold]{len(results)} websites checked in {elapsed} seconds[/]")
        
        # Credits
        self.console.print("\n[dim]Twitter : @palenath[/]")
        self.console.print("[dim]Github : https://github.com/megadose/holehe[/]")
        self.console.print("[dim]For BTC Donations : 1FHDM49QfZX6pJmhjLE5tB2K6CaTLMZpXZ[/]\n")

    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 2: PHONE INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_phone_collector(self):
        """Phone Intelligence - Carrier, GPS, Timezone with Dynamic UI"""
        from ...engines.network.phone_locator import PhoneTracer
        from rich.console import Group
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    PHONE INTELLIGENCE (OSINT)        [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        phone = input("📱 Enter phone number (with country code): ").strip()
        if not phone:
            self.console.print("[red]❌ No phone number provided[/]")
            self._pause()
            return
        
        # Setup Dynamic UI via ProgressManager
        pm = get_manager(self.console)
        progress, table, task = pm.create(
            target_name=phone,
            total=4,
            table_columns=[
                ("Property", {"style": "cyan", "width": 20}),
                ("Value", {"style": "green"})
            ]
        )
        
        # Activity log
        activity_log = []
        def add_activity(msg):
            activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            if len(activity_log) > 5:
                activity_log.pop(0)

        api_key = os.getenv('OPENCAGE_API_KEY')
        tracer = PhoneTracer(opencage_api_key=api_key)
        
        # Setup bypass console for Live
        original_stdout = sys.stdout
        live_console = Console(file=original_stdout, force_terminal=True)

        try:
            with Live(pm.render_display(progress, table, activity_log), console=live_console, refresh_per_second=4, screen=False) as live:
                # Helper to update both activity and UI
                def live_activity(msg):
                    add_activity(msg)
                    live.update(pm.render_display(progress, table, activity_log))

                with LogRedirector(live_activity):
                    # Step 1: Basic Info & Validation
                    live_activity(f"🔍 Validating {phone}...")
                    result = tracer.trace_phone(phone)
                    time.sleep(0.5)
                    pm.update_task(progress, task, description="Validating")
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    if not result.is_valid:
                        live_activity(f"❌ Validation failed: {result.error or 'Invalid number'}")
                        self._pause()
                        return

                    if result.country: pm.add_table_row(table, "Country Code", result.country)
                    if result.region: pm.add_table_row(table, "Region", result.region)
                    
                    # Step 2: Carrier
                    live_activity("📡 Fetching carrier information...")
                    pm.update_task(progress, task, description="Carrier search")
                    if result.carrier:
                        pm.add_table_row(table, "Carrier", f"[cyan]{result.carrier}[/]")
                    if result.number_type:
                        type_icon = "📱" if "mobile" in result.number_type.lower() else "☎️"
                        pm.add_table_row(table, "Number Type", f"{type_icon} {result.number_type}")
                    time.sleep(0.5)
                    pm.update_task(progress, task)
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    # Step 3: Location
                    live_activity("📍 Resolving geographic location...")
                    pm.update_task(progress, task, description="Locating")
                    if result.location:
                        pm.add_table_row(table, "Location", result.location)
                    time.sleep(0.5)
                    pm.update_task(progress, task)
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    # Step 4: GPS
                    live_activity("🗺️ Retrieving GPS coordinates...")
                    pm.update_task(progress, task, description="GPS tracking")
                    if result.gps_coordinates:
                        gps = result.gps_coordinates
                        lat = gps.get('lat', 0)
                        lng = gps.get('lng', 0)
                        pm.add_table_row(table, "📍 GPS Latitude", f"{lat:.6f}")
                        pm.add_table_row(table, "📍 GPS Longitude", f"{lng:.6f}")
                        pm.add_table_row(table, "📍 Coordinates", f"[yellow]{lat:.4f}, {lng:.4f}[/]")
                        live_activity(f"✅ GPS resolved: {lat:.4f}, {lng:.4f}")
                    else:
                        reason = result.geocoding_error or "Not available"
                        pm.add_table_row(table, "📍 GPS Status", f"[dim]{reason}[/]")
                        live_activity(f"⚠️ GPS resolution skipped: {reason}")
                    
                    pm.update_task(progress, task, description="Analysis complete", completed=4)
                    live_activity("🏁 Analysis complete.")
                    time.sleep(0.3)
                    live.update(pm.render_display(progress, table, activity_log, progress_title="Analysis Progress"))
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⚠️ Scan interrupted by user.[/]")
            ui_event("Phone OSINT scan interrupted", state, style="yellow")
            return
            
        state.add_log(f"✓ Phone OSINT: {phone}")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 3: IP INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_ip_collector(self):
        """IP Intelligence - Geolocation, ISP, ASN, WHOIS with Dynamic UI"""
        from ...engines.network.ip_collector import IPCollector
        from rich.console import Group
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    IP INTELLIGENCE (OSINT)          [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        ip = input("🌐 Enter IP address: ").strip()
        if not ip:
            self.console.print("[red]❌ No IP address provided[/]")
            self._pause()
            return
        
        # Setup Dynamic UI via ProgressManager
        pm = get_manager(self.console)
        progress, table, task = pm.create(
            target_name=ip,
            total=5,
            table_columns=[
                ("Category", {"style": "cyan", "width": 20}),
                ("Property", {"style": "dim", "width": 20}),
                ("Value", {"style": "green"})
            ]
        )
        
        # Activity log
        activity_log = []
        def add_activity(msg):
            activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            if len(activity_log) > 5:
                activity_log.pop(0)

        collector = IPCollector()
        
        # Setup bypass console for Live
        original_stdout = sys.stdout
        live_console = Console(file=original_stdout, force_terminal=True)

        try:
            with Live(pm.render_display(progress, table, activity_log), console=live_console, refresh_per_second=4, screen=False) as live:
                # Helper to update both activity and UI
                def update_ui(msg):
                    add_activity(msg)
                    live.update(pm.render_display(progress, table, activity_log))

                with LogRedirector(update_ui):
                    # Step 1: Initialize and Basic check
                    update_ui(f"🌐 Querying databases for {ip}...")
                    result = collector.collect(ip)
                    time.sleep(0.5)
                    pm.update_task(progress, task, description="Initializing")
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    # Step 2: Basic Info & Type
                    update_ui("🔍 Resolving IP type and basic metadata...")
                    pm.update_task(progress, task, description="Data analysis")
                    ip_type = result.get('type', 'unknown')
                    type_color = "cyan" if ip_type == "public" else "yellow"
                    pm.add_table_row(table, "Basic Info", "Type", f"[{type_color}]{ip_type.upper()}[/]")
                    time.sleep(0.3)
                    pm.update_task(progress, task)
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    # Step 3: Geolocation
                    update_ui("📍 Locating IP address...")
                    pm.update_task(progress, task, description="Geolocating")
                    if result.get('geolocation'):
                        geo = result['geolocation']
                        country_display = geo.get('country', 'Unknown')
                        if geo.get('country_code3'):
                            country_display += f" ({geo.get('country_code3')})"
                        elif geo.get('country_code'):
                            country_display += f" ({geo.get('country_code')})"
                        
                        pm.add_table_row(table, "Geolocation", "Country", f"[cyan]{country_display}[/]")
                        if geo.get('continent_code'):
                            pm.add_table_row(table, "Geolocation", "Continent", f"[yellow]{geo.get('continent_code')}[/]")
                        
                        location = f"{geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}"
                        pm.add_table_row(table, "Geolocation", "City/Region", location)
                        pm.add_table_row(table, "Geolocation", "Coordinates", f"{geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
                        update_ui(f"✅ Located in {geo.get('city', 'N/A')}, {country_display}")
                        
                        if geo.get('timezone'):
                            pm.add_table_row(table, "Geolocation", "Timezone", geo.get('timezone'))
                        if geo.get('currency'):
                            pm.add_table_row(table, "Geolocation", "Currency", f"[green]{geo.get('currency')}[/]")
                        if geo.get('area_code') and geo.get('area_code') != '0':
                            pm.add_table_row(table, "Geolocation", "Area Code", str(geo.get('area_code')))
                        if geo.get('accuracy'):
                            pm.add_table_row(table, "Geolocation", "Accuracy", f"{geo.get('accuracy')} km")
                        
                        # Step 4: Provider Info
                        update_ui("🏢 Identifying ISP and ASN data...")
                        pm.update_task(progress, task, description="ISP identification")
                        isp = geo.get('isp') or geo.get('org') or 'N/A'
                        pm.add_table_row(table, "Provider", "ISP", f"[cyan]{isp}[/]")
                        
                        asn_val = geo.get('asn') or result.get('asn', {}).get('asn') or 'N/A'
                        org_val = geo.get('organization') or result.get('asn', {}).get('asn_description') or 'N/A'
                        pm.add_table_row(table, "Provider", "ASN", f"AS{asn_val} {org_val}")
                    time.sleep(0.5)
                    pm.update_task(progress, task)
                    live.update(pm.render_display(progress, table, activity_log))
                    
                    # Step 5: Network Data (Reverse DNS & WHOIS)
                    update_ui("🛡️ Analyzing network records and WHOIS...")
                    pm.update_task(progress, task, description="Network audit")
                    rdns = result.get('reverse_dns')
                    if rdns:
                        pm.add_table_row(table, "Network", "Reverse DNS", f"[cyan]{rdns}[/]")
                    
                    geo = result.get('geolocation', {})
                    if geo.get('ptr'):
                        pm.add_table_row(table, "Network", "PTR Record", f"[yellow]{geo.get('ptr')}[/]")
                        
                    if result.get('whois'):
                        whois = result['whois']
                        if whois.get('asn_description'):
                            pm.add_table_row(table, "WHOIS", "Description", whois['asn_description'])
                    
                    pm.update_task(progress, task, description="Analysis complete", completed=5)
                    update_ui("🏁 IP Analysis complete.")
                    time.sleep(0.3)
                    live.update(pm.render_display(progress, table, activity_log, progress_title="IP Analysis Progress"))
        except KeyboardInterrupt:
            self.console.print("\n[yellow]⚠️ Scan interrupted by user.[/]")
            ui_event("IP OSINT scan interrupted", state, style="yellow")
            return
            
        state.add_log(f"✓ IP OSINT: {ip}")
        self._pause()
    
    def _configure_social_settings(self, settings):
        """Interactive configuration for SocialEngine advanced settings"""
        self.console.print("\n[bold cyan]🔧 SOCIAL ENGINE ADVANCED SETTINGS[/]")
        
        if input(f"🔹 Enable Permutations (strict)? (current: {settings['permute']}) (y/n): ").lower() == "y":
            settings["permute"] = True
            settings["permuteall"] = False
        if input(f"🔹 Enable Permutations (all variations)? (current: {settings['permuteall']}) (y/n): ").lower() == "y":
            settings["permuteall"] = True
            settings["permute"] = False
            
        f_val = input(f"🔹 Site Filter (e.g. cat=social) (current: {settings['filter']}): ").strip()
        if f_val: settings["filter"] = f_val
        
        if input(f"🔹 No NSFW sites? (current: {settings['no_nsfw']}) (y/n): ").lower() == "y":
            settings["no_nsfw"] = True
            
        proxy_val = input(f"🔹 Proxy (e.g. http://127.0.0.1:8080) (current: {settings['proxy']}): ").strip()
        if proxy_val: settings["proxy"] = proxy_val
        
        if input(f"🔹 Dump HTML content? (current: {settings['dump']}) (y/n): ").lower() == "y":
            settings["dump"] = True

        timeout_val = input(f"🔹 Timeout (seconds) (current: {settings['timeout']}): ").strip()
        if timeout_val.isdigit(): settings["timeout"] = int(timeout_val)

        concurrent_val = input(f"🔹 Max Concurrent Requests (current: {settings['max_concurrent']}): ").strip()
        if concurrent_val.isdigit(): settings["max_concurrent"] = int(concurrent_val)

        if input(f"🔹 Skip site updates? (current: {settings['no_update']}) (y/n): ").lower() == "y":
            settings["no_update"] = True

        if input(f"🔹 Enable Verbose mode? (current: {settings['verbose']}) (y/n): ").lower() == "y":
            settings["verbose"] = True

        self.console.print("[green]✓ Settings updated.[/]")

    def run_social_engine(self):
        """Social Media Search (SocialEngine)"""
        if not SOCIAL_ENGINE_AVAILABLE:
            msg = "SocialEngine is not available"
            if 'SOCIAL_ENGINE_ERROR' in globals() and SOCIAL_ENGINE_ERROR:
                msg += f": {SOCIAL_ENGINE_ERROR}"
            self.console.print(f"[red]❌ {msg}[/]")
            self.console.print("[yellow]💡 Tip: install missing dependency (e.g. pip install chardet) or run: pip install . in your venv[/]")
            self._pause()
            return

        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    SOCIAL MEDIA SEARCH (SENTINELLE)   [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        self.console.print("1. Search by Username")
        self.console.print("2. Search by Email")
        self.console.print("3. Search from File (.txt)")
        self.console.print("4. Setup AI (API Key)")
        self.console.print("5. Advanced Settings (Permutations, Proxy, Filters)")
        self.console.print("0. Back")

        self.logger.info("Opened SocialEngine menu; options presented to user")
        ui_event("Opened SocialEngine menu", state, style="white")
        
        choice = input("\n> ").strip()
        if choice == "0":
            return
            
        engine = SocialEngine(self.console)
        
        if choice == "4":
            if engine.setup_ai():
                self.console.print("[bold green]✓ AI Setup successful![/]")
            else:
                self.console.print("[bold red]❌ AI Setup failed.[/]")
            self._pause()
            return
            
        # Default settings
        settings = {
            "ai": False,
            "export_csv": False,
            "export_pdf": False,
            "export_json": False,
            "permute": False,
            "permuteall": False,
            "filter": None,
            "no_nsfw": False,
            "proxy": None,
            "timeout": 30,
            "max_concurrent": 30,
            "dump": False,
            "no_update": False,
            "verbose": False
        }

        if choice == "5":
            self._configure_social_settings(settings)
            # Re-ask for main choice after settings
            self.console.print("\n[bold cyan]Select search type with current settings:[/]")
            self.console.print("1. Search by Username")
            self.console.print("2. Search by Email")
            self.console.print("3. Search from File (.txt)")
            choice = input("\n> ").strip()

        if choice not in ["1", "2", "3"]:
            return

        targets = []
        search_type = "username"
        
        if choice == "3":
            file_path = input("📂 Enter path to .txt file: ").strip()
            if not os.path.exists(file_path):
                self.console.print(f"[red]❌ File not found: {file_path}[/]")
                self._pause()
                return
            with open(file_path, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            search_type = input("Type of targets (u: username, e: email): ").strip().lower()
            search_type = "username" if search_type == "u" else "email"
        else:
            search_type = "username" if choice == "1" else "email"
            target = input(f"👤 Enter {search_type} to search: ").strip()
            if not target: return
            targets = [target]

        if not settings["ai"]:
            settings["ai"] = input("✨ Use AI for analysis? (y/n): ").strip().lower() == "y"
        
        # Ask for exports
        self.console.print("\n[bold cyan]Export Results?[/]")
        if input("📄 CSV? (y/n): ").lower() == "y": settings["export_csv"] = True
        if input("📕 PDF? (y/n): ").lower() == "y": settings["export_pdf"] = True
        if input("📦 JSON? (y/n): ").lower() == "y": settings["export_json"] = True

        # Permutation support
        if search_type == "username" and (settings["permute"] or settings["permuteall"]) and len(targets) > 0:
            try:
                from ...engines.social.modules.utils.permute import Permute
                way = "all" if settings["permuteall"] else "strict"
                permute = Permute(targets)
                targets = permute.gather(way)
                self.console.print(f"[yellow]🔄 Permuted usernames into {len(targets)} variations[/]")
            except ImportError:
                self.console.print("[red]⚠️ Permutation module not found, skipping...[/]")

        # We need to run the search for each target and handle UI
        # To maintain the rich UI, we'll do the loop here and call engine.run_search for each target
        # OR we can let the engine handle the loop but we need to pass UI elements.
        
        # In SocialEngine.run_search, I added support for pro
        # gress and table.
        # Let's use that.
        
        for target_val in targets:
            self.console.print(f"[yellow]⏳ Starting search for [bold]{target_val}[/]...[/]\n")
            self.logger.info("Starting SocialEngine search for target: %s (type=%s)", target_val, search_type)
            ui_event(f"Started SocialEngine search: {target_val} (type={search_type})", state, style="cyan")
            
            # Setup UI components for this target via ProgressManager
            from ...engines.social.modules.whatsmyname.list_operations import readList
            from ...engines.social.modules.utils.filter import applyFilters
            from ...engines.social import config as bb_config
            
            data_list = readList(search_type, bb_config)
            sites = applyFilters(data_list["sites"], bb_config)
            
            pm = get_manager(self.console)
            progress, table, search_task = pm.create(
                target_name=target_val,
                total=len(sites),
                table_columns=[
                    ("Site", {"style": "cyan", "width": 20}),
                    ("Status", {"width": 10}),
                    ("URL", {"style": "bright_white"}),
                    ("Information", {"style": "dim"})
                ]
            )
            
            settings["progress"] = progress
            settings["task_id"] = search_task
            settings["table"] = table
            
            # Real-time activity log for the UI
            activity_log = []
            def add_activity(msg):
                if not msg:
                    return
                # Clean up message (remove ANSI codes if any)
                clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', str(msg))
                activity_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {clean_msg}")
                if len(activity_log) > 5:
                    activity_log.pop(0)
            
            try:
                # Setup bypass console for Live with force_terminal
                original_stdout = sys.stdout
                live_console = Console(file=original_stdout, force_terminal=True)

                try:
                    with Live(pm.render_display(progress, table, activity_log), console=live_console, refresh_per_second=4, screen=False) as live:
                        def live_activity(msg):
                            if msg:
                                add_activity(msg)
                            live.update(pm.render_display(progress, table, activity_log))

                        with LogRedirector(live_activity):
                            # We slightly modify the engine call to ensure it updates frequently
                            settings["log_callback"] = live_activity
                            results = asyncio.run(engine.run_search([target_val], search_type, settings))
                            live.update(pm.render_display(progress, table, activity_log))
                    
                    found = results[0]["found"] if results else 0
                    if found > 0:
                        self.console.print(f"\n[bold green]✓ Found {found} accounts for {target_val}![/]")
                        if results[0].get("ai_analysis"):
                            self.console.print("\n[bold cyan]✨ SENTINELLE AI ANALYSIS[/]")
                            self.console.print(results[0]["ai_analysis"])
                    
                    state.add_log(f"✓ SocialEngine {search_type}: {target_val} ({found} found)")
                    self.logger.info("SocialEngine search completed for %s (found=%d)", target_val, found)
                    ui_event(f"SocialEngine completed: {target_val} (found={found})", state, style="green")

                except KeyboardInterrupt:
                    self.console.print("\n[yellow]⚠️ Search interrupted by user.[/]")
                    ui_event(f"SocialEngine interrupted: {target_val}", state, style="yellow")
                    # Break the outer target loop too if interrupted
                    targets = [] 
                    break
            except Exception as e:
                self.console.print(f"[red]❌ SocialEngine Error for {target_val}: {str(e)}[/]")
                # import traceback
                # self.console.print(traceback.format_exc())

        state.add_log(f"✓ SocialEngine batch completed: {len(targets)} targets")
        if len(targets) > 1:
            self.console.print(f"\n[bold green]🏁 Batch search completed for {len(targets)} targets.[/]")
            
        self._pause()

    # ═══════════════════════════════════════════════════════════════════════════════
    # UTILITY
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _pause(self):
        """Wait for user to continue"""
        input("\n[dim]Press Enter to continue...[/]")
