import time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from ..core.state import state

class ModuleRunner:
    def __init__(self, console: Console):
        self.console = console

    def run_apt_attribution(self):
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
        from intelligence.traffic_analyzer import EncryptedTrafficAnalyzer
        
        self.console.print("\n[bold cyan]═══ Encrypted Traffic Analysis ═══[/]\n")
        
        analyzer = EncryptedTrafficAnalyzer()
        session = {
            'client_hello': {
                'version': 771,
                'ciphers': [49195, 49199, 52393],
                'extensions': [0, 10, 11, 13],
                'curves': [23, 24, 25],
                'point_formats': [0],
            }
        }
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing TLS session..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = analyzer.analyze_session(session)
        
        table = Table(title="Traffic Analysis Results", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("JA3 Fingerprint", result.get('ja3', 'N/A')[:32] + "...")
        table.add_row("Threat Detected", "✓ Yes" if result.get('threat_detected') else "✗ No")
        table.add_row("Threat Type", result.get('threat_type', 'None'))
        
        self.console.print(table)
        if result.get('threat_detected'):
            state.threats_detected += 1
            state.add_log("Threat detected in traffic analysis", "red")
        
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
        
        self.console.print("\n[bold cyan]═══ Persona Profiler ═══[/]\n")
        target = input("Enter target identifier (email/username): ")
        profiler = PersonaProfiler()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating psychological profile..."), console=self.console) as progress:
            task = progress.add_task("", total=None)
            time.sleep(2)
            profile = profiler.create_profile(target)
        
        self.console.print(f"\n[bold green]Profile Created for {target}[/]\n")
        
        table = Table(title="OCEAN Personality Assessment", box=box.ROUNDED)
        table.add_column("Trait", style="cyan")
        table.add_column("Score", style="green")
        
        for trait, score in profile['personality'].items():
            table.add_row(trait.capitalize(), f"{score:.1%}")
        
        self.console.print(table)
        state.add_log(f"Persona profile: {target}")
        self._pause()

    def run_malware_genome(self):
        self.console.print("[yellow]Module under development[/]")
        self._pause()

    def _pause(self):
        input("\nPress Enter to continue...")
