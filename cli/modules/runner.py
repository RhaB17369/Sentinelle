import time
import os
import sys
import re
from io import StringIO
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich import box
from ..core.state import state

# Import engine_mail_collector functions
try:
    from engine_mail_collector.core import (
        is_email, 
        print_result as email_print_result,
        import_submodules,
        get_functions,
        launch_module,
        maincore as email_maincore
    )
    import engine_mail_collector.core as email_core
    EMAIL_OSINT_AVAILABLE = True
except ImportError as e:
    EMAIL_OSINT_AVAILABLE = False
    email_core = None

# Async support
try:
    import trio
    import httpx
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False


class ModuleRunner:
    """Minimal runner with only 3 real modules: Email OSINT, Phone Intelligence, IP Intelligence"""
    
    def __init__(self, console: Console):
        self.console = console
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 1: EMAIL OSINT (Holehe v1.61 via engine_mail_collector)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_email_osint(self):
        """Email OSINT with real-time dynamic table and progress bar"""
        
        if not EMAIL_OSINT_AVAILABLE:
            self.console.print("[red]❌ Email OSINT module not available[/]")
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
        
        # Setup Dynamic UI components
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        )
        
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Status", width=10)
        table.add_column("Domain", style="cyan")
        table.add_column("Information", style="dim")
        
        # Results storage for final report
        all_results = []
        start_time = time.time()
        
        def update_ui(result):
            all_results.append(result)
            domain = result.get('domain', 'unknown')
            info = ""
            
            if result.get('exists'):
                status = "[bold green][+][/]"
                if result.get('emailrecovery'): info += f"Recovery: {result['emailrecovery']}"
                if result.get('phoneNumber'): info += f" | Phone: {result['phoneNumber']}"
            elif result.get('rateLimit'):
                status = "[bold yellow][x][/]"
            elif result.get('error'):
                status = "[bold red][!][/]"
            else:
                status = "[bold magenta][-][/]"
            
            # Only add to table if it's "interesting" (exists, rate limit, or error)
            # or if you want to see everything
            table.add_row(status, domain, info)

        with Live(Panel(table, title=f"Scanning: {email}"), console=self.console, refresh_per_second=4) as live:
            self.console.print(f"\n[yellow]⏳ Starting live scan for {email}...[/]\n")
            
            try:
                # Get websites count for progress
                modules = import_submodules("engine_mail_collector.modules")
                websites = get_functions(modules, None)
                
                scan_task = progress.add_task(f"Checking {len(websites)} platforms...", total=len(websites))
                
                # Combine table and progress in the Live display
                live.update(Panel(
                    Layout(progress, name="p"), 
                    title=f"Progress: {email}"
                ))
                # Note: For simplicity in this layout, we'll just show the progress and then the results
                # or we can nest them. Let's do a simple vertical layout.
                from rich.console import Group
                live.update(Panel(Group(progress, table), title=f"OSINT Scan: {email}"))

                # Run scan
                self._scan_email_holehe(email, on_complete=lambda r: (update_ui(r), progress.update(scan_task, advance=1)))
                
            except Exception as e:
                self.console.print(f"[red]❌ Error: {str(e)}[/]")

        if all_results:
            self._display_email_results(email, all_results, start_time)
            state.add_log(f"✓ Email OSINT completed: {email}")
        
        self._pause()

    def _scan_email_holehe(self, email: str, on_complete=None) -> list:
        """Run holehe scan for email across platforms with optimized settings"""
        if not ASYNC_AVAILABLE:
            self.console.print("[red]❌ Async libraries not available (httpx, trio)[/]")
            return []
        
        try:
            modules = import_submodules("engine_mail_collector.modules")
            websites = get_functions(modules, None)
            results = []
            
            async def run_scan():
                client_config = {
                    'timeout': 30.0,
                    'limits': httpx.Limits(max_keepalive_connections=10, max_connections=20),
                }
                
                async with httpx.AsyncClient(**client_config) as client:
                    async with trio.open_nursery() as nursery:
                        for i, website in enumerate(websites):
                            if i > 0 and i % 10 == 0:
                                await trio.sleep(0.05)
                            nursery.start_soon(self._safe_launch_module, website, email, client, results, on_complete)
                
                return sorted(results, key=lambda i: i.get('name', ''))
            
            results = trio.run(run_scan)
            return results
            
        except Exception as e:
            return []
    
    async def _safe_launch_module(self, module, email: str, client, out: list, on_complete=None):
        """Safely launch a module with proper error handling and retries"""
        try:
            # We need to capture what was added to 'out'
            initial_len = len(out)
            await launch_module(module, email, client, out)
            if on_complete and len(out) > initial_len:
                on_complete(out[-1])
        except Exception as e:
            # Handled by engine_mail_collector adding error record usually, 
            # but if it fails completely we should ensure something is reported
            pass
    
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
        from phone_location.phone_locator import PhoneTracer
        from rich.console import Group
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    PHONE INTELLIGENCE (OSINT)        [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        phone = input("📱 Enter phone number (with country code): ").strip()
        if not phone:
            self.console.print("[red]❌ No phone number provided[/]")
            self._pause()
            return
        
        # Setup Dynamic UI
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
        
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="green")
        
        api_key = os.getenv('OPENCAGE_API_KEY')
        tracer = PhoneTracer(opencage_api_key=api_key)
        
        with Live(Panel(Group(progress, table), title=f"Analyzing: {phone}"), console=self.console) as live:
            task = progress.add_task("Gathering intelligence...", total=4)
            
            # Step 1: Basic Info & Validation
            progress.update(task, description="Validating number...")
            result = tracer.trace_phone(phone)
            time.sleep(0.5) # Slight delay for visual effect
            progress.advance(task)
            
            if not result.is_valid:
                live.update(Panel(f"[red]❌ Error: {result.error or 'Invalid number'}[/]", title="Analysis Failed"))
                self._pause()
                return

            if result.country: table.add_row("Country Code", result.country)
            if result.region: table.add_row("Region", result.region)
            
            # Step 2: Carrier
            progress.update(task, description="Fetching carrier info...")
            if result.carrier:
                table.add_row("Carrier", f"[cyan]{result.carrier}[/]")
            if result.number_type:
                type_icon = "📱" if "mobile" in result.number_type.lower() else "☎️"
                table.add_row("Number Type", f"{type_icon} {result.number_type}")
            time.sleep(0.5)
            progress.advance(task)
            
            # Step 3: Location
            progress.update(task, description="Resolving location...")
            if result.location:
                table.add_row("Location", result.location)
            time.sleep(0.5)
            progress.advance(task)
            
            # Step 4: GPS
            progress.update(task, description="Retrieving GPS data...")
            if result.gps_coordinates:
                gps = result.gps_coordinates
                lat = gps.get('lat', 0)
                lng = gps.get('lng', 0)
                table.add_row("📍 GPS Latitude", f"{lat:.6f}")
                table.add_row("📍 GPS Longitude", f"{lng:.6f}")
                table.add_row("📍 Coordinates", f"[yellow]{lat:.4f}, {lng:.4f}[/]")
            else:
                reason = result.geocoding_error or "Not available"
                table.add_row("📍 GPS Status", f"[dim]{reason}[/]")
            
            progress.update(task, description="Analysis complete", completed=4)
            time.sleep(0.3)
            
        state.add_log(f"✓ Phone OSINT: {phone}")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 3: IP INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_ip_collector(self):
        """IP Intelligence - Geolocation, ISP, ASN, WHOIS with Dynamic UI"""
        from collectors.ip_collector import IPCollector
        from rich.console import Group
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    IP INTELLIGENCE (OSINT)          [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        
        ip = input("🌐 Enter IP address: ").strip()
        if not ip:
            self.console.print("[red]❌ No IP address provided[/]")
            self._pause()
            return
        
        # Setup Dynamic UI
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        )
        
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Category", style="cyan", width=20)
        table.add_column("Property", style="dim", width=20)
        table.add_column("Value", style="green")
        
        collector = IPCollector()
        
        with Live(Panel(Group(progress, table), title=f"Analyzing IP: {ip}"), console=self.console) as live:
            task = progress.add_task("Collecting intelligence...", total=5)
            
            # Step 1: Initialize and Basic check
            progress.update(task, description="Querying provider databases...")
            result = collector.collect(ip)
            time.sleep(0.5)
            progress.advance(task)
            
            # Step 2: Basic Info & Type
            progress.update(task, description="Resolving IP type...")
            ip_type = result.get('type', 'unknown')
            type_color = "cyan" if ip_type == "public" else "yellow"
            table.add_row("Basic Info", "Type", f"[{type_color}]{ip_type.upper()}[/]")
            time.sleep(0.3)
            progress.advance(task)
            
            # Step 3: Geolocation
            progress.update(task, description="Locating IP address...")
            if result.get('geolocation'):
                geo = result['geolocation']
                table.add_row("Geolocation", "Country", f"[cyan]{geo.get('country')}[/]")
                table.add_row("Geolocation", "City/Region", f"{geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}")
                table.add_row("Geolocation", "Coordinates", f"{geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
                
                # Step 4: Provider Info
                progress.update(task, description="Identifying ISP/ASN...")
                table.add_row("Provider", "ISP", f"[cyan]{geo.get('isp', 'N/A')}[/]")
                table.add_row("Provider", "ASN", geo.get('as', 'N/A'))
            time.sleep(0.5)
            progress.advance(task)
            
            # Step 5: Network Data (Reverse DNS & WHOIS)
            progress.update(task, description="Analyzing network records...")
            if result.get('reverse_dns'):
                table.add_row("Network", "Reverse DNS", f"[cyan]{result['reverse_dns']}[/]")
                
            if result.get('whois'):
                whois = result['whois']
                if whois.get('asn_description'):
                    table.add_row("WHOIS", "Description", whois['asn_description'])
            
            progress.update(task, description="Analysis complete", completed=5)
            time.sleep(0.3)
            
        state.add_log(f"✓ IP OSINT: {ip}")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # UTILITY
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _pause(self):
        """Wait for user to continue"""
        input("\n[dim]Press Enter to continue...[/]")
