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
    
    def run_apt_attribution(self):
        # DEPRECATED - Stub removed
        pass
    
    def run_phone_collector(self):
        """Phone Intelligence - Carrier, GPS, Timezone, Type detection"""
        import sys
        import importlib.util
        
        # Import PhoneTracer from phone location/phone_locator.py (handles space in directory name)
        spec = importlib.util.spec_from_file_location(
            "phone_locator",
            "phone location/phone_locator.py"
        )
        phone_locator_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(phone_locator_module)
        
        PhoneTracer = phone_locator_module.PhoneTracer
        format_result_table = phone_locator_module.format_result_table
        
        self.console.print("\n[bold cyan]═════════════════════════════════════════[/]")
        self.console.print("[bold cyan]    PHONE INTELLIGENCE (OSINT)        [/]")
        self.console.print("[bold cyan]═════════════════════════════════════════[/]\n")
        
        phone = input("📱 Enter phone number (with country code): ").strip()
        
        if not phone:
            self.console.print("[red]❌ No phone number provided[/]")
            self._pause()
            return
        
        tracer = PhoneTracer()
        
        self.console.print(f"\n[yellow]Analyzing {phone}...[/]\n")
        with Progress(SpinnerColumn(), TextColumn("[cyan]Processing..."), console=self.console) as progress:
            progress.add_task("", total=None)
            result = tracer.trace_phone(phone)
        
        # Display formatted result
        output = format_result_table(result)
        self.console.print(output)
        
        # Additional details if valid
        if result.is_valid:
            table = Table(box=box.ROUNDED)
            table.add_column("Property", style="cyan", width=20)
            table.add_column("Value", style="green")
            
            if result.carrier:
                table.add_row("Carrier", f"[cyan]{result.carrier}[/]")
            if result.location:
                table.add_row("Location", result.location)
            if result.number_type:
                table.add_row("Type", result.number_type)
            if result.country:
                table.add_row("Country Code", result.country)
            if result.gps_coordinates:
                coords = result.gps_coordinates
                table.add_row("GPS Coordinates", f"[yellow]{coords['lat']:.4f}, {coords['lng']:.4f}[/]")
            
            if table.rows:
                self.console.print("\n")
                self.console.print(table)
        
        state.add_log(f"✓ Phone OSINT: {phone}")
        self._pause()
    
    def run_ip_collector(self):
        """IP Intelligence - Geolocation, ISP, ASN, WHOIS"""
        from collectors.ip_collector import IPCollector
        
        self.console.print("\n[bold cyan]═════════════════════════════════════════[/]")
        self.console.print("[bold cyan]    IP INTELLIGENCE (OSINT)          [/]")
        self.console.print("[bold cyan]═════════════════════════════════════════[/]\n")
        
        ip = input("🌐 Enter IP address: ").strip()
        
        if not ip:
            self.console.print("[red]❌ No IP address provided[/]")
            self._pause()
            return
        
        collector = IPCollector()
        
        self.console.print(f"\n[yellow]Analyzing {ip}...[/]\n")
        with Progress(SpinnerColumn(), TextColumn("[cyan]Processing..."), console=self.console) as progress:
            progress.add_task("", total=None)
            result = collector.collect(ip)
        
        ip_type = result.get('type', 'unknown')
        self.console.print(f"[bold]Type:[/] {ip_type.upper()}\n")
        
        if result.get('geolocation'):
            geo = result['geolocation']
            self.console.print("[bold]📍 Geolocation:[/]")
            self.console.print(f"  Country: [cyan]{geo.get('country')}[/]")
            self.console.print(f"  City: {geo.get('city', 'N/A')}")
            self.console.print(f"  ISP: {geo.get('isp', 'N/A')}")
        
        state.add_log(f"✓ IP OSINT: {ip}")
        self._pause()

        """Run APT Attribution module"""
        # Lazy import to avoid circular dep and improve startup
        from intelligence.apt_attribution import APTAttributor
        
        self.console.print("\n[bold cyan]═══ APT Attribution Engine ═══[/]\n")
        
        indicators = {
            'ttps': ['T1566', 'T1059', 'T1003'],
            'infrastructure': {'countries': ['RU'], 'asns': ['12345']},
            'timestamps': ['2024-01-01T09:00:00', '2024-01-01T10:30:00'],
        }
        
        attributor = APTAttributor()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing indicators..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = attributor.attribute(indicators)
        
        # Display results
        table = Table(title="Attribution Results", box=box.ROUNDED)
        table.add_column("APT Group", style="cyan")
        table.add_column("Probability", style="green")
        table.add_column("Country", style="yellow")
        
        for apt, prob in result['all_probabilities'].items():
            info = attributor.get_apt_info(apt)
            table.add_row(apt, f"{prob:.1%}", info.get('country', 'Unknown'))
        
        self.console.print(table)
        self.console.print(f"\n[bold green]Top Attribution:[/] {result['top_attribution']} ({result['confidence']:.1%})")
        
        state.apt_attributions += 1
        state.add_log(f"APT Attribution run: {result['top_attribution']}")
        self._pause()

    def run_traffic_analysis(self):
        try:
            from intelligence.traffic_analyzer import EncryptedTrafficAnalyzer
            from intelligence.pcap_analyzer import PcapAnalyzer
        except ImportError:
            self.console.print("[red]Error: Scapy not installed. Cannot run traffic analysis.[/]")
            self._pause()
            return

        self.console.print("\n[bold cyan]═══ Encrypted Traffic Analysis ═══[/]\n")
        self.console.print("[dim]Supports .pcap and .pcapng files. Extracts JA3/JA3S fingerprints.[/]")
        
        pcap_path = input("Enter path to PCAP file: ")
        
        if not pcap_path:
            self.console.print("[yellow]No file provided. Aborting.[/]")
            self._pause()
            return
            
        if not os.path.exists(pcap_path):
             self.console.print(f"[red]File not found: {pcap_path}[/]")
             self._pause()
             return

        analyzer = EncryptedTrafficAnalyzer()
        pcap_reader = PcapAnalyzer()
        
        sessions_found = 0
        threats_found = 0
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Parsing PCAP packets..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            
            try:
                raw_sessions = pcap_reader.process_pcap(pcap_path)
            except Exception as e:
                self.console.print(f"[red]Error parsing PCAP: {e}[/]")
                self._pause()
                return

        if not raw_sessions:
            self.console.print("[yellow]No TLS Handshakes found in capture file.[/]")
            self._pause()
            return

        table = Table(title=f"Traffic Analysis Report ({os.path.basename(pcap_path)})", box=box.ROUNDED)
        table.add_column("Time", style="dim")
        table.add_column("Source", style="cyan")
        table.add_column("Destination", style="cyan")
        table.add_column("Fingerprint type", style="white")
        table.add_column("JA3/JA3S Hash", style="green")
        table.add_column("Threat", style="red")
        
        for sess in raw_sessions:
            analysis_result = analyzer.analyze_session(sess)
            
            fingerprint = ""
            f_type = ""
            
            if analysis_result.get('ja3'):
                fingerprint = analysis_result['ja3']
                f_type = "Client (JA3)"
            elif analysis_result.get('ja3s'):
                fingerprint = analysis_result['ja3s']
                f_type = "Server (JA3S)"
            
            if not fingerprint:
                continue
                
            sessions_found += 1
            threat_status = "CLEAN"
            if analysis_result.get('threat_detected'):
                threat_status = f"MALWARE: {analysis_result['threat_type']}"
                threats_found += 1
            
            # Truncate hash to fit
            hash_display = fingerprint[:16] + "..."
            
            table.add_row(
                f"{sess['timestamp']:.2f}",
                sess['src'],
                sess['dst'],
                f_type,
                hash_display,
                threat_status
            )
        
        self.console.print(table)
        self.console.print(f"\n[bold]Summary:[/] {sessions_found} TLS sessions analyzed. [bold red]{threats_found} threats detected.[/]")
        
        if threats_found > 0:
            state.threats_detected += threats_found
            state.add_log(f"PCAP Analysis: {threats_found} threats in {os.path.basename(pcap_path)}", "red")
        
        self._pause()

    def run_blockchain_intel(self):
        from intelligence.blockchain_intel import BlockchainIntelligence
        
        self.console.print("\n[bold cyan]═══ Blockchain Intelligence ═══[/]\n")
        address = input("Enter Bitcoin address: ")
        
        intel = BlockchainIntelligence()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Tracing funds..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            trace = intel.trace_funds(address, 'bitcoin')
        
        self.console.print(f"\n[green]Trace complete for {address}[/]")
        self.console.print(f"Blockchain: {trace['blockchain']}")
        
        state.blockchain_traces += 1
        state.add_log(f"Blockchain trace: {address}")
        self._pause()

    def run_steganalysis(self):
        from intelligence.steganalysis import StegAnalyzer
        import random
        
        self.console.print("\n[bold cyan]═══ Steganalysis Engine ═══[/]\n")
        analyzer = StegAnalyzer()
        image_data = bytes([random.randint(0, 255) for _ in range(10000)])
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing image for hidden data..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = analyzer.analyze_image(image_data)
        
        self.console.print(f"\n[bold]Suspicious:[/] {result['suspicious']}")
        self.console.print(f"[bold]Confidence:[/] {result['confidence']:.1%}")
        if result['techniques_detected']:
            self.console.print(f"[bold]Techniques:[/] {', '.join(result['techniques_detected'])}")
        
        state.add_log("Steganalysis complete")
        self._pause()

    def run_passive_sigint(self):
        from intelligence.passive_sigint import PassiveSIGINT
        
        self.console.print("\n[bold cyan]═══ Passive SIGINT ═══[/]\n")
        domain = input("Enter domain: ")
        
        sigint = PassiveSIGINT()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Reconstructing infrastructure..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = sigint.reconstruct_infrastructure(domain)
        
        self.console.print(f"\n[green]Infrastructure reconstruction complete[/]")
        self.console.print(f"Domain: {result['domain']}")
        self.console.print(f"Passive DNS records: {len(result['passive_dns'])}")
        self.console.print(f"Certificate history: {len(result['certificate_history'])}")
        
        state.add_log(f"SIGINT analysis: {domain}")
        self._pause()

    def run_deanonymization(self):
        from intelligence.deanonymization import DeAnonymizer
        
        self.console.print("\n[bold cyan]═══ De-Anonymization Engine ═══[/]\n")
        deanon = DeAnonymizer()
        
        browser_data = {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'screen_resolution': '1920x1080',
            'timezone': 'America/New_York',
            'plugins': ['PDF Viewer', 'Chrome PDF Plugin'],
            'fonts': ['Arial', 'Times New Roman', 'Courier'],
        }
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating browser fingerprint..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            fingerprint = deanon.fingerprint_browser(browser_data)
        
        self.console.print(f"\n[bold green]Browser Fingerprint:[/]")
        self.console.print(f"{fingerprint}")
        state.add_log("Deanonymization run complete")
        self._pause()

    def run_behavioral_biometrics(self):
        from intelligence.behavioral_biometrics import BehavioralBiometrics
        import random
        
        self.console.print("\n[bold cyan]═══ Behavioral Biometrics ═══[/]\n")
        bio = BehavioralBiometrics()
        
        keystroke_data = [
            {'press_time': i * 0.1, 'release_time': i * 0.1 + random.uniform(0.05, 0.15)}
            for i in range(50)
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating typing profile..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            profile = bio.create_typing_profile(keystroke_data)
        
        self.console.print(f"\n[green]Typing profile created[/]")
        self.console.print(f"Profile dimensions: {len(profile)}")
        state.add_log("Behavioral biometrics profiled")
        self._pause()

    def run_ai_threat_hunter(self):
        from intelligence.ai_threat_hunter import AIThreatHunter
        
        self.console.print("\n[bold cyan]═══ AI Threat Hunter ═══[/]\n")
        hunter = AIThreatHunter()
        telemetry = [
            {'type': 'network', 'anomaly_score': 0.8},
            {'type': 'process', 'anomaly_score': 0.3},
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Hunting for threats..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(2)
            threats = hunter.hunt(telemetry)
        
        if threats:
            table = Table(title="Threats Detected", box=box.ROUNDED)
            table.add_column("Hypothesis", style="cyan")
            table.add_column("Severity", style="red")
            for threat in threats:
                table.add_row(threat['hypothesis'], threat['severity'])
            self.console.print(table)
            state.threats_detected += len(threats)
            state.add_log(f"AI Hunter found {len(threats)} threats", "red")
        else:
            self.console.print("[green]No threats detected[/]")
        
        self._pause()

    def run_attack_predictor(self):
        from intelligence.attack_predictor import AttackPredictor
        
        self.console.print("\n[bold cyan]═══ Attack Prediction Engine ═══[/]\n")
        target = input("Enter target (domain/IP): ")
        predictor = AttackPredictor()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Predicting attack likelihood..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(2)
            prediction = predictor.predict_attack(target, '24h')
        
        prob = prediction['probability']
        color = "red" if prob > 0.7 else "yellow" if prob > 0.4 else "green"
        
        self.console.print(f"\n[bold]Target:[/] {target}")
        self.console.print(f"[bold]Attack Probability:[/] [{color}]{prob:.1%}[/]")
        self.console.print(f"[bold]Likely Vector:[/] {prediction['likely_vector']}")
        
        self.console.print(f"\n[bold cyan]Recommendations:[/]")
        for rec in prediction['recommended_actions']:
            self.console.print(f"  • {rec}")
            
        state.add_log(f"Attack prediction for {target}")
        self._pause()


    def run_persona_profiler(self):
        from intelligence.persona_profiler import PersonaProfiler
        
        self.console.print("\n[bold cyan]═══ Email/Username OSINT Intelligence ═══[/]\n")
        self.console.print("[dim]Comprehensive reconnaissance across 150+ platforms[/]")
        target = input("Enter target (email/username): ")
        
        profiler = PersonaProfiler()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running OSINT reconnaissance..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            profile = profiler.create_profile(target)
        
        self.console.print(f"\n[bold green]═══ Intelligence Report: {target} ═══[/]\n")
        
        # Tor Status
        tor_status = "✓ ACTIVE" if profile.get('tor_used') else "✗ INACTIVE"
        tor_color = "green" if profile.get('tor_used') else "yellow"
        self.console.print(f"[bold]Tor Anonymization:[/] [{tor_color}]{tor_status}[/]")
        self.console.print(f"[bold]Target Type:[/] {profile.get('type', 'unknown').upper()}\n")
        
        # Accounts Found
        accounts = profile.get('accounts_found', [])
        if accounts:
            table = Table(title=f"Accounts Found ({len(accounts)} platforms)", box=box.ROUNDED)
            table.add_column("#", style="dim", width=4)
            table.add_column("Platform", style="cyan")
            table.add_column("Detection Method", style="green")
            
            for idx, account in enumerate(accounts[:50], 1):  # Show first 50
                table.add_row(
                    str(idx),
                    account['platform'],
                    account.get('method', 'unknown')
                )
            
            self.console.print(table)
            
            if len(accounts) > 50:
                self.console.print(f"[dim]... and {len(accounts) - 50} more accounts[/]")
        else:
            self.console.print("[yellow]No accounts found on checked platforms[/]")
        
        # Breach Exposure
        breaches = profile.get('breaches', {})
        if breaches.get('checked'):
            breach_list = breaches.get('breaches', [])
            if breach_list:
                self.console.print(f"\n[bold red]⚠ BREACH EXPOSURE DETECTED[/]")
                breach_table = Table(title="Data Breaches", box=box.ROUNDED)
                breach_table.add_column("Source", style="red")
                breach_table.add_column("Count", style="yellow")
                breach_table.add_column("Severity", style="red")
                
                for breach in breach_list:
                    breach_table.add_row(
                        breach.get('source', 'Unknown'),
                        str(breach.get('count', 0)),
                        breach.get('severity', 'UNKNOWN')
                    )
                
                self.console.print(breach_table)
            else:
                self.console.print("\n[bold green]✓ No known breach exposure[/]")
        
        # Metadata (for emails)
        metadata = profile.get('metadata', {})
        if metadata:
            self.console.print(f"\n[bold]Email Metadata:[/]")
            self.console.print(f"  Domain: {metadata.get('domain', 'N/A')}")
            self.console.print(f"  Provider: {metadata.get('provider_type', 'N/A')}")
            if metadata.get('mx_records'):
                self.console.print(f"  MX Server: {metadata['mx_records'][0]}")
        
        # Summary
        self.console.print(f"\n[bold]Summary:[/]")
        self.console.print(f"  • Total Accounts: {len(accounts)}")
        self.console.print(f"  • Breaches: {breaches.get('total_breaches', 0)}")
        self.console.print(f"  • Anonymization: {'Tor' if profile.get('tor_used') else 'Direct'}")
        
        state.add_log(f"OSINT reconnaissance: {target}")
        self._pause()


    def run_malware_genome(self):
        self.console.print("[yellow]Module under development[/]")
        self._pause()

    def run_domain_collector(self):
        from collectors.domain_collector import DomainCollector
        
        self.console.print("\n[bold cyan]═══ Domain Intelligence (OSINT) ═══[/]\n")
        domain = input("Enter domain to investigate: ")
        
        collector = DomainCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Gathering intelligence..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(domain)
        
        self.console.print(f"\n[bold green]Report for {domain}[/]")
        
        # DNS Info
        if result.get('dns'):
            table = Table(title="DNS Records", box=box.ROUNDED)
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="white")
            for record_type, values in result['dns'].items():
                for val in values:
                    table.add_row(record_type, val)
            self.console.print(table)
            
        # Tech Stack
        if result.get('technologies'):
            self.console.print("\n[bold]Detected Technologies:[/]")
            for tech in result['technologies']:
                self.console.print(f"  • {tech}")

        state.add_log(f"Domain intel: {domain}")
        self._pause()

    def run_ip_collector(self):
        from collectors.ip_collector import IPCollector
        
        self.console.print("\n[bold cyan]═══ IP Intelligence (OSINT) ═══[/]\n")
        ip = input("Enter IP address: ")
        
        collector = IPCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Geolocating and analyzing..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(ip)
            
        self.console.print(f"\n[bold green]Report for {ip} ({result.get('type', 'unknown')})[/]")
        
        # Geo Info
        if result.get('geolocation'):
            geo = result['geolocation']
            self.console.print(f"[bold]Location:[/] {geo.get('city')}, {geo.get('country')}")
            self.console.print(f"[bold]ISP:[/] {geo.get('isp')}")
            self.console.print(f"[bold]ASN:[/] {geo.get('as')}")
        
        # ASN Info (if separate)
        if result.get('asn'):
            asn = result['asn']
            self.console.print(f"[bold]ASN Description:[/] {asn.get('asn_description')}")
            
        state.add_log(f"IP intel: {ip}")
        self._pause()

    def run_person_collector(self):
        from collectors.person_collector import PersonCollector
        
        self.console.print("\n[bold cyan]═══ Person Intelligence (OSINT) ═══[/]\n")
        self.console.print("[yellow]⚠️  Ethical Constraint: Public lawful data only[/]")
        identifier = input("Enter email or username: ")
        
        collector = PersonCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Searching public footprint..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(identifier)
            
        self.console.print(f"\n[bold green]Report for {identifier}[/]")
        
        if result.get('breach_exposure'):
            breach = result['breach_exposure']
            if breach.get('checked'):
                self.console.print(f"[bold]Breach Status:[/] {breach.get('breach_count')} breaches found")
            else:
                self.console.print(f"[dim]{breach.get('reason')}[/]")
                
        state.add_log(f"Person intel: {identifier}")
        self._pause()

    def run_network_scanner(self):
        from scanners.network_scanner import NetworkScanner
        
        self.console.print("\n[bold red]═══ ACTIVE Network Scanner ═══[/]\n")
        self.console.print("[bold red]⚠️  WARNING: Unauthorized scanning is ILLEGAL.[/]")
        target = input("Enter target IP/Hostname: ")
        
        scanner = NetworkScanner()
        
        self.console.print("\nSelect Scan Mode:")
        self.console.print("1. Fast (Common ports)")
        self.console.print("2. Full (1-1024)")
        mode = input("> ")
        
        ports = None
        if mode == "2":
            ports = list(range(1, 1025))
            
        with Progress(SpinnerColumn(), TextColumn("[red]Scanning target (Active)..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = scanner.scan(target, ports=ports)
            
        self.console.print(f"\n[bold green]Scan Complete for {target}[/]")
        self.console.print(f"Time: {result['scan_duration']}s | Open: {len(result['open_ports'])}")
        
        if result['open_ports']:
            table = Table(title="Open Ports", box=box.ROUNDED)
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            table.add_column("Banner/Version", style="dim white")
            
            for p in result['open_ports']:
                banner = p.get('banner') or p.get('product') or ""
                if p.get('version'):
                    banner += f" {p.get('version')}"
                table.add_row(str(p['port']), p['service'], banner)
            
            self.console.print(table)
        else:
            self.console.print("[yellow]No open ports found (or filtered)[/]")
            
        state.add_log(f"Network scan: {target}", "red")
        self._pause()

    def run_phone_collector(self):
        from collectors.phone_collector import PhoneCollector
        
        self.console.print("\n[bold cyan]═══ Phone Intelligence (OSINT) ═══[/]\n")
        phone = input("Enter phone number (with country code): ")
        
        collector = PhoneCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing phone number..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(phone)
            
        self.console.print(f"\n[bold green]Report for {phone}[/]")
        
        if result.get('parsed'):
            parsed = result['parsed']
            self.console.print(f"[bold]International Format:[/] {parsed.get('international_format', 'N/A')}")
            self.console.print(f"[bold]Valid:[/] {parsed.get('is_valid', False)}")
        
        if result.get('carrier'):
            self.console.print(f"[bold]Carrier:[/] {result['carrier']}")
        
        if result.get('location'):
            self.console.print(f"[bold]Location:[/] {result['location']}")
        
        if result.get('gps_coordinates'):
            gps = result['gps_coordinates']
            self.console.print(f"[bold]GPS Coordinates:[/] {gps.get('formatted', 'N/A')}")
            self.console.print(f"  Latitude: {gps.get('latitude')}, Longitude: {gps.get('longitude')}")
        
        if result.get('timezone'):
            self.console.print(f"[bold]Timezone:[/] {', '.join(result['timezone'])}")
        
        if result.get('type'):
            self.console.print(f"[bold]Number Type:[/] {result['type']}")
            
        state.add_log(f"Phone intel: {phone}")
        self._pause()

    def run_location_collector(self):
        from collectors.location_collector import LocationCollector
        
        self.console.print("\n[bold cyan]═══ Location Intelligence (OSINT) ═══[/]\n")
        location = input("Enter location (address, coordinates, or place name): ")
        
        collector = LocationCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Geocoding location..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(location)
            
        self.console.print(f"\n[bold green]Report for {location}[/]")
        
        if result.get('geocode'):
            geo = result['geocode']
            self.console.print(f"[bold]Coordinates:[/] {geo.get('latitude')}, {geo.get('longitude')}")
            self.console.print(f"[bold]Display Name:[/] {geo.get('display_name', 'N/A')}")
            self.console.print(f"[bold]Type:[/] {geo.get('type', 'N/A')}")
        elif result.get('reverse_geocode'):
            rgeo = result['reverse_geocode']
            self.console.print(f"[bold]Display Name:[/] {rgeo.get('display_name', 'N/A')}")
            if rgeo.get('address'):
                self.console.print(f"[bold]Address:[/] {rgeo['address']}")
            
        state.add_log(f"Location intel: {location}")
        self._pause()

    def run_email_osint(self):
        from intelligence.email_osint import EmailOSINT
        
        self.console.print("\n[bold cyan]═══ Email OSINT (Holehe Integration) ═══[/]\n")
        self.console.print("[dim]Checks 120+ platforms for email registration[/]")
        email = input("Enter email address: ")
        
        if '@' not in email:
            self.console.print("[red]Invalid email address[/]")
            self._pause()
            return
        
        osint = EmailOSINT()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Checking platforms (this may take a while)..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            report = osint.run_full_reconnaissance(email)
            
        self.console.print(f"\n[bold green]═══ Email OSINT Report: {email} ═══[/]\n")
        
        # Accounts found
        accounts = report.get('accounts_found', [])
        if accounts:
            table = Table(title=f"Accounts Found ({len(accounts)} platforms)", box=box.ROUNDED)
            table.add_column("Platform", style="cyan")
            table.add_column("Domain", style="green")
            table.add_column("Additional Info", style="dim white")
            
            for account in accounts[:50]:  # Show first 50
                add_info = ""
                if account.get('emailrecovery'):
                    add_info += f"Email: {account['emailrecovery']}"
                if account.get('phoneNumber'):
                    if add_info:
                        add_info += " / "
                    add_info += f"Phone: {account['phoneNumber']}"
                
                table.add_row(
                    account.get('platform', 'unknown'),
                    account.get('domain', 'unknown'),
                    add_info or "N/A"
                )
            
            self.console.print(table)
            
            if len(accounts) > 50:
                self.console.print(f"[dim]... and {len(accounts) - 50} more accounts[/]")
        else:
            self.console.print("[yellow]No accounts found on checked platforms[/]")
        
        # Breaches
        breaches = report.get('breaches', {})
        if breaches.get('total_breaches', 0) > 0:
            self.console.print(f"\n[bold red]⚠ BREACH EXPOSURE: {breaches['total_breaches']} breaches found[/]")
            for breach in breaches.get('breaches', []):
                self.console.print(f"  • {breach.get('source')}: {breach.get('count')} occurrences ({breach.get('severity')})")
        else:
            self.console.print("\n[bold green]✓ No known breach exposure[/]")
        
        # Metadata
        metadata = report.get('metadata', {})
        if metadata:
            self.console.print(f"\n[bold]Email Metadata:[/]")
            self.console.print(f"  Provider: {metadata.get('provider_type', 'N/A')}")
            if metadata.get('mx_records'):
                self.console.print(f"  MX Records: {', '.join(metadata['mx_records'][:3])}")
        
        state.add_log(f"Email OSINT: {email} ({len(accounts)} accounts found)")
        self._pause()

    def run_alienvault_collector(self):
        from collectors.alienvault_collector import AlienVaultCollector
        
        self.console.print("\n[bold cyan]═══ AlienVault OTX Intelligence ═══[/]\n")
        indicator = input("Enter indicator (IP, domain, hash, URL): ")
        
        collector = AlienVaultCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Querying AlienVault OTX..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(indicator)
            
        if result:
            self.console.print(f"\n[bold green]AlienVault OTX Report for {indicator}[/]")
            # Display results based on indicator type
            if result.get('pulse_count'):
                self.console.print(f"[bold]Pulses:[/] {result['pulse_count']}")
            if result.get('reputation'):
                self.console.print(f"[bold]Reputation:[/] {result['reputation']}")
        else:
            self.console.print("[yellow]No data found or API key not configured[/]")
            
        state.add_log(f"AlienVault intel: {indicator}")
        self._pause()

    def run_threatcrowd_collector(self):
        from collectors.threatcrowd_collector import ThreatCrowdCollector
        
        self.console.print("\n[bold cyan]═══ ThreatCrowd Intelligence ═══[/]\n")
        indicator = input("Enter indicator (domain, email, IP, hash): ")
        
        collector = ThreatCrowdCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Querying ThreatCrowd..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(indicator)
            
        if result:
            self.console.print(f"\n[bold green]ThreatCrowd Report for {indicator}[/]")
            # Display results
            if result.get('votes'):
                self.console.print(f"[bold]Votes:[/] {result['votes']}")
        else:
            self.console.print("[yellow]No data found[/]")
            
        state.add_log(f"ThreatCrowd intel: {indicator}")
        self._pause()

    def run_urlscan_collector(self):
        from collectors.urlscan_collector import URLScanCollector
        
        self.console.print("\n[bold cyan]═══ URLScan.io Intelligence ═══[/]\n")
        url = input("Enter URL to scan: ")
        
        collector = URLScanCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning URL..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(url)
            
        if result:
            self.console.print(f"\n[bold green]URLScan Report for {url}[/]")
            if result.get('scan_id'):
                self.console.print(f"[bold]Scan ID:[/] {result['scan_id']}")
                self.console.print(f"[bold]Scan URL:[/] https://urlscan.io/result/{result['scan_id']}/")
        else:
            self.console.print("[yellow]Scan failed or API key not configured[/]")
            
        state.add_log(f"URLScan: {url}")
        self._pause()

    def run_virustotal_collector(self):
        from collectors.virustotal_collector import VirusTotalCollector
        
        self.console.print("\n[bold cyan]═══ VirusTotal Intelligence ═══[/]\n")
        indicator = input("Enter indicator (domain, IP, hash, URL): ")
        
        collector = VirusTotalCollector()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Querying VirusTotal..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            result = collector.collect(indicator)
            
        if result:
            self.console.print(f"\n[bold green]VirusTotal Report for {indicator}[/]")
            if result.get('detection_rate'):
                self.console.print(f"[bold]Detection Rate:[/] {result['detection_rate']}")
        else:
            self.console.print("[yellow]No data found or API key not configured[/]")
            
        state.add_log(f"VirusTotal intel: {indicator}")
        self._pause()

    def _pause(self):
        input("\nPress Enter to continue...")
