import time
import os
import sys
import re
from io import StringIO
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
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
        """Email OSINT using engine_mail_collector (Holehe v1.61) - Check email on 150+ platforms"""
        
        if not EMAIL_OSINT_AVAILABLE:
            self.console.print("[red]❌ Email OSINT module not available[/]")
            self.console.print("[dim]Missing dependencies: engine_mail_collector, httpx, trio[/]")
            self._pause()
            return
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]  EMAIL OSINT - Holehe v1.61           [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        self.console.print("[dim]Analyzes 150+ platforms for email registration[/]")
        self.console.print("[dim]Detects: GitHub, LinkedIn, Twitter, Discord, etc.[/]\n")
        
        email = input("📧 Enter email address: ").strip()
        
        if not email:
            self.console.print("[red]❌ No email provided[/]")
            self._pause()
            return
        
        # Validate email format
        if not is_email(email):
            self.console.print(f"[red]❌ Invalid email format: {email}[/]")
            self._pause()
            return
        
        self.console.print(f"\n[yellow]⏳ Scanning {email} across 150+ platforms...[/]")
        self.console.print("[dim]This may take 15-30 seconds[/]\n")
        
        # Run holehe scan asynchronously
        try:
            with Progress(SpinnerColumn(), TextColumn("[cyan]Checking platforms..."), console=self.console) as progress:
                task = progress.add_task("", total=None)
                
                # Run the email scan
                results = self._scan_email_holehe(email)
        
            if results:
                self._display_email_results(email, results)
                state.add_log(f"✓ Email OSINT completed: {email}")
            else:
                self.console.print("[yellow]⚠️  Scan completed but no results[/]")
                
        except Exception as e:
            self.console.print(f"[red]❌ Error during scan: {str(e)}[/]")
        
        self._pause()
    
    def _scan_email_holehe(self, email: str) -> list:
        """Run holehe scan for email across platforms"""
        if not ASYNC_AVAILABLE:
            self.console.print("[red]❌ Async libraries not available (httpx, trio)[/]")
            return []
        
        try:
            # Import holehe modules
            modules = import_submodules("engine_mail_collector.modules")
            websites = get_functions(modules, None)
            
            # Run async scan
            results = []
            
            async def run_scan():
                async with httpx.AsyncClient(timeout=10) as client:
                    async with trio.open_nursery() as nursery:
                        for website in websites:
                            nursery.start_soon(launch_module, website, email, client, results)
                
                return sorted(results, key=lambda i: i.get('name', ''))
            
            results = trio.run(run_scan)
            return results
            
        except Exception as e:
            self.console.print(f"[dim]Scan error: {str(e)}[/]")
            return []
    
    def _display_email_results(self, email: str, results: list):
        """Display email OSINT results"""
        
        # Filter results
        accounts_found = [r for r in results if r.get('exists') == True]
        errors = [r for r in results if r.get('error') == True]
        rate_limits = [r for r in results if r.get('rateLimit') == True]
        
        # Header
        self.console.print(f"\n[bold green]{'═' * 50}[/]")
        self.console.print(f"[bold green]  📧 EMAIL SCAN REPORT: {email}[/]")
        self.console.print(f"[bold green]{'═' * 50}[/]\n")
        
        # Summary stats
        summary_table = Table(box=box.SIMPLE)
        summary_table.add_row("Total Platforms Checked", str(len(results)))
        summary_table.add_row("[green]Accounts Found", f"[green]{len(accounts_found)}")
        summary_table.add_row("[yellow]Rate Limited", f"[yellow]{len(rate_limits)}")
        summary_table.add_row("[red]Errors", f"[red]{len(errors)}")
        self.console.print(summary_table)
        
        # Accounts found
        if accounts_found:
            self.console.print(f"\n[bold green]✓ DETECTED ACCOUNTS ({len(accounts_found)}):[/]\n")
            accounts_table = Table(title="Platforms with Active Accounts", box=box.ROUNDED)
            accounts_table.add_column("Platform", style="cyan", width=20)
            accounts_table.add_column("Domain", style="green", width=25)
            accounts_table.add_column("Additional Info", style="dim white", width=30)
            
            for result in accounts_found[:50]:
                add_info = ""
                if result.get('emailrecovery'):
                    add_info += f"Recovery: {result['emailrecovery']}"
                if result.get('phoneNumber'):
                    if add_info:
                        add_info += " | "
                    add_info += f"Phone: {result['phoneNumber']}"
                if result.get('others') and isinstance(result['others'], dict):
                    if 'FullName' in result['others']:
                        if add_info:
                            add_info += " | "
                        add_info += f"Name: {result['others']['FullName']}"
                
                accounts_table.add_row(
                    result.get('name', 'unknown'),
                    result.get('domain', 'unknown'),
                    add_info or "—"
                )
            
            self.console.print(accounts_table)
            
            if len(accounts_found) > 50:
                self.console.print(f"\n[dim]... and {len(accounts_found) - 50} more accounts[/]")
        else:
            self.console.print("[yellow]⚠️  No accounts detected on scanned platforms[/]\n")
        
        # Rate limits
        if rate_limits:
            self.console.print(f"\n[yellow]⚠️  Rate Limited on {len(rate_limits)} platforms (retry later)[/]")
        
        # Errors
        if errors:
            self.console.print(f"\n[red]❌ Errors on {len(errors)} platforms (API/network issues)[/]")

    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 2: PHONE INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_phone_collector(self):
        """Phone Intelligence - Carrier, GPS, Timezone, Type detection"""
        import os
        from phone_location.phone_locator import PhoneTracer, format_result_table
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    PHONE INTELLIGENCE (OSINT)        [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        self.console.print("[dim]Analyzes international phone numbers[/]")
        self.console.print("[dim]Detects: Carrier, Location, GPS, Timezone, Type[/]\n")
        
        phone = input("📱 Enter phone number (with country code, e.g., +33612345678): ").strip()
        
        if not phone:
            self.console.print("[red]❌ No phone number provided[/]")
            self._pause()
            return
        
        # Get API key from environment and pass it to PhoneTracer
        api_key = os.getenv('OPENCAGE_API_KEY')
        tracer = PhoneTracer(opencage_api_key=api_key)
        
        self.console.print(f"\n[yellow]⏳ Analyzing {phone}...[/]\n")
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Processing..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = tracer.trace_phone(phone)
        
        # Display formatted result first
        self.console.print(format_result_table(result))
        
        # If valid, show detailed table
        if result.is_valid:
            self.console.print("\n[bold cyan]═══════════════════════════════════════[/]\n")
            
            table = Table(box=box.ROUNDED)
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="green")
            
            if result.country:
                table.add_row("Country Code", result.country)
            
            if result.region:
                table.add_row("Region", result.region)
            
            if result.carrier:
                table.add_row("Carrier", f"[cyan]{result.carrier}[/]")
            
            if result.number_type:
                type_icon = "📱" if "mobile" in result.number_type.lower() else "☎️"
                table.add_row("Number Type", f"{type_icon} {result.number_type}")
            
            if result.location:
                table.add_row("Location", result.location)
            
            if result.gps_coordinates:
                gps = result.gps_coordinates
                lat = gps.get('lat', 'N/A')
                lng = gps.get('lng', 'N/A')
                if lat != 'N/A' and lng != 'N/A':
                    table.add_row("📍 GPS Latitude", f"[yellow]{lat:.6f}[/]")
                    table.add_row("📍 GPS Longitude", f"[yellow]{lng:.6f}[/]")
                    table.add_row("📍 Coordinates", f"[yellow]{lat:.4f}, {lng:.4f}[/]")
                else:
                    table.add_row("📍 GPS", "[dim]Set OPENCAGE_API_KEY for coordinates[/]")
            
            self.console.print(table)
        
        state.add_log(f"✓ Phone OSINT: {phone}")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 3: IP INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_ip_collector(self):
        """IP Intelligence - Geolocation, ISP, ASN, WHOIS"""
        from collectors.ip_collector import IPCollector
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]    IP INTELLIGENCE (OSINT)          [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        self.console.print("[dim]Analyzes IP addresses[/]")
        self.console.print("[dim]Detects: Geolocation, ISP, ASN, Type[/]\n")
        
        ip = input("🌐 Enter IP address: ").strip()
        
        if not ip:
            self.console.print("[red]❌ No IP address provided[/]")
            self._pause()
            return
        
        collector = IPCollector()
        
        self.console.print(f"\n[yellow]⏳ Analyzing {ip}...[/]\n")
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Processing..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(ip)
        
        self.console.print(f"\n[bold green]═══════════════════════════════════════[/]")
        self.console.print(f"[bold green]  IP ANALYSIS: {ip}  [/]")
        self.console.print(f"[bold green]═══════════════════════════════════════[/]\n")
        
        # IP Type
        ip_type = result.get('type', 'unknown')
        type_color = "cyan" if ip_type == "public" else "yellow"
        self.console.print(f"[bold]Type:[/] [{type_color}]{ip_type.upper()}[/]\n")
        
        # Geolocation
        if result.get('geolocation'):
            geo = result['geolocation']
            self.console.print("[bold]📍 Geolocation:[/]")
            self.console.print(f"  Country: [cyan]{geo.get('country')}[/]")
            self.console.print(f"  City: {geo.get('city', 'N/A')}")
            self.console.print(f"  Region: {geo.get('region', 'N/A')}")
            self.console.print(f"  Timezone: {geo.get('timezone', 'N/A')}")
            self.console.print(f"  Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
        
        # ISP/ASN
        if result.get('geolocation'):
            geo = result['geolocation']
            self.console.print(f"\n[bold]🏢 Internet Provider:[/]")
            self.console.print(f"  ISP: [cyan]{geo.get('isp', 'N/A')}[/]")
            self.console.print(f"  Organization: {geo.get('org', 'N/A')}")
            self.console.print(f"  ASN: {geo.get('as', 'N/A')}")
        
        # Reverse DNS
        if result.get('reverse_dns'):
            self.console.print(f"\n[bold]🔗 Reverse DNS:[/]")
            self.console.print(f"  Hostname: [cyan]{result['reverse_dns']}[/]")
        
        # WHOIS
        if result.get('whois'):
            whois = result['whois']
            self.console.print(f"\n[bold]📋 WHOIS Data:[/]")
            if whois.get('asn'):
                self.console.print(f"  ASN: {whois['asn']}")
            if whois.get('asn_description'):
                self.console.print(f"  Description: {whois['asn_description']}")
            if whois.get('asn_country_code'):
                self.console.print(f"  Country Code: {whois['asn_country_code']}")
        
        state.add_log(f"✓ IP OSINT: {ip}")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # UTILITY
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def _pause(self):
        """Wait for user to continue"""
        input("\n[dim]Press Enter to continue...[/]")
