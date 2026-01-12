import time
import os
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from ..core.state import state


class ModuleRunner:
    """Minimal runner with only 3 real modules: Email OSINT, Phone Intelligence, IP Intelligence"""
    
    def __init__(self, console: Console):
        self.console = console
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 1: EMAIL OSINT (Holehe v1.61)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_email_osint(self):
        """Email OSINT using Holehe v1.61 - Check email on 150+ platforms"""
        from intelligence.email_osint import EmailOSINT
        
        self.console.print("\n[bold cyan]═══════════════════════════════════════[/]")
        self.console.print("[bold cyan]  EMAIL OSINT - Holehe v1.61 Integration  [/]")
        self.console.print("[bold cyan]═══════════════════════════════════════[/]\n")
        self.console.print("[dim]Checks 150+ platforms for email registration[/]")
        self.console.print("[dim]Includes: GitHub, LinkedIn, Twitter, Facebook, etc.[/]\n")
        
        email = input("📧 Enter email address: ").strip()
        
        if not email or '@' not in email:
            self.console.print("[red]❌ Invalid email address[/]")
            self._pause()
            return
        
        osint = EmailOSINT()
        
        self.console.print(f"\n[yellow]⏳ Scanning 150+ platforms for {email}...[/]")
        self.console.print("[dim]This may take 10-15 seconds[/]\n")
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Checking platforms..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            report = osint.run_full_reconnaissance(email)
        
        self.console.print(f"\n[bold green]═══════════════════════════════════════[/]")
        self.console.print(f"[bold green]  REPORT: {email}  [/]")
        self.console.print(f"[bold green]═══════════════════════════════════════[/]\n")
        
        # Accounts found
        accounts = report.get('accounts_found', [])
        if accounts:
            self.console.print(f"[bold green]✓ Found {len(accounts)} accounts:[/]\n")
            table = Table(title=f"Detected Accounts ({len(accounts)})", box=box.ROUNDED)
            table.add_column("Platform", style="cyan", width=20)
            table.add_column("Domain", style="green", width=25)
            table.add_column("Additional Info", style="dim white")
            
            for account in accounts[:50]:  # Show first 50
                add_info = ""
                if account.get('emailrecovery'):
                    add_info += f"Recovery: {account['emailrecovery']}"
                if account.get('phoneNumber'):
                    if add_info:
                        add_info += " | "
                    add_info += f"Phone: {account['phoneNumber']}"
                
                table.add_row(
                    account.get('platform', 'unknown'),
                    account.get('domain', 'unknown'),
                    add_info or "—"
                )
            
            self.console.print(table)
            
            if len(accounts) > 50:
                self.console.print(f"\n[dim]... and {len(accounts) - 50} more accounts[/]")
        else:
            self.console.print("[yellow]⚠️  No accounts detected on checked platforms[/]")
        
        # Breaches
        breaches = report.get('breaches', {})
        if breaches.get('total_breaches', 0) > 0:
            self.console.print(f"\n[bold red]⚠️  BREACH EXPOSURE DETECTED[/]")
            self.console.print(f"[bold red]Found in {breaches['total_breaches']} breaches:[/]\n")
            for breach in breaches.get('breaches', []):
                self.console.print(f"  • [red]{breach.get('source')}[/]: {breach.get('count')} occurrences ({breach.get('severity')})")
        else:
            self.console.print(f"\n[bold green]✓ No known breach exposure[/]")
        
        # Metadata
        metadata = report.get('metadata', {})
        if metadata:
            self.console.print(f"\n[bold]Email Metadata:[/]")
            self.console.print(f"  Provider: [cyan]{metadata.get('provider_type', 'N/A')}[/]")
            if metadata.get('mx_records'):
                self.console.print(f"  MX Records: {', '.join(metadata['mx_records'][:3])}")
        
        state.add_log(f"✓ Email OSINT: {email} ({len(accounts)} accounts)")
        self._pause()
    
    # ═══════════════════════════════════════════════════════════════════════════════
    # MODULE 2: PHONE INTELLIGENCE
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def run_phone_collector(self):
        """Phone Intelligence - Carrier, GPS, Timezone, Type detection"""
        from collectors.phone_collector import PhoneCollector
        
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
        
        collector = PhoneCollector()
        
        self.console.print(f"\n[yellow]⏳ Analyzing {phone}...[/]\n")
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Processing..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(phone)
        
        self.console.print(f"\n[bold green]═══════════════════════════════════════[/]")
        self.console.print(f"[bold green]  PHONE ANALYSIS: {phone}  [/]")
        self.console.print(f"[bold green]═══════════════════════════════════════[/]\n")
        
        table = Table(box=box.ROUNDED)
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="green")
        
        # Parsed info
        if result.get('parsed'):
            parsed = result['parsed']
            table.add_row("Valid", "✓ Yes" if parsed.get('is_valid') else "✗ No")
            table.add_row("Format", parsed.get('international_format', 'N/A'))
            table.add_row("Country", parsed.get('country', 'N/A'))
        
        # Carrier
        if result.get('carrier'):
            table.add_row("Carrier", f"[cyan]{result['carrier']}[/]")
        
        # Location
        if result.get('location'):
            table.add_row("Location", result['location'])
        
        # Type
        if result.get('type'):
            type_icon = "📱" if result['type'] == "MOBILE" else "☎️"
            table.add_row("Number Type", f"{type_icon} {result['type']}")
        
        # GPS
        if result.get('gps_coordinates'):
            gps = result['gps_coordinates']
            table.add_row("GPS", gps.get('formatted', 'N/A'))
            table.add_row("Latitude", str(gps.get('latitude', 'N/A')))
            table.add_row("Longitude", str(gps.get('longitude', 'N/A')))
        
        # Timezone
        if result.get('timezone'):
            table.add_row("Timezone", ', '.join(result['timezone']))
        
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
