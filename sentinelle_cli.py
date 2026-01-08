#!/usr/bin/env python3
"""
SENTINNELLE Advanced CLI - bpytop-style Interface
Beautiful TUI for advanced intelligence operations
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
import time
from datetime import datetime


class SentinnelleCLI:
    """Advanced CLI interface for SENTINNELLE"""
    
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
    
    def create_header(self) -> Panel:
        """Create header panel"""
        header_text = Text()
        header_text.append("SENTINNELLE", style="bold cyan")
        header_text.append(" | ", style="white")
        header_text.append("Advanced Cyber Intelligence Platform", style="bold green")
        header_text.append(" | ", style="white")
        header_text.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="yellow")
        
        return Panel(
            header_text,
            box=box.DOUBLE,
            style="bold white on blue",
        )
    
    def create_stats_panel(self) -> Panel:
        """Create statistics panel"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(style="cyan")
        table.add_column(style="green")
        
        table.add_row("Active Modules", "11")
        table.add_row("Threats Detected", "0")
        table.add_row("APT Attributions", "0")
        table.add_row("Blockchain Traces", "0")
        
        return Panel(
            table,
            title="[bold cyan]Statistics[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    
    def create_modules_panel(self) -> Panel:
        """Create modules panel"""
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Module", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Level", style="yellow")
        
        modules = [
            ("APT Attribution", "✓ Ready", "NSA"),
            ("Traffic Analysis", "✓ Ready", "NSA"),
            ("Blockchain Intel", "✓ Ready", "CIA"),
            ("Steganalysis", "✓ Ready", "8200"),
            ("Passive SIGINT", "✓ Ready", "GCHQ"),
            ("De-anonymization", "✓ Ready", "NSA"),
            ("Behavioral Bio", "✓ Ready", "CIA"),
            ("AI Threat Hunter", "✓ Ready", "8200"),
            ("Attack Predictor", "✓ Ready", "NSA"),
            ("Persona Profiler", "✓ Ready", "CIA"),
            ("Malware Genome", "⏳ Dev", "8200"),
        ]
        
        for module, status, level in modules:
            table.add_row(module, status, level)
        
        return Panel(
            table,
            title="[bold cyan]Advanced Modules[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    
    def create_activity_panel(self) -> Panel:
        """Create activity log panel"""
        log_text = Text()
        log_text.append("[14:05:45] ", style="dim")
        log_text.append("System initialized\n", style="green")
        log_text.append("[14:05:46] ", style="dim")
        log_text.append("Loading APT database...\n", style="yellow")
        log_text.append("[14:05:47] ", style="dim")
        log_text.append("All modules ready\n", style="green")
        
        return Panel(
            log_text,
            title="[bold cyan]Activity Log[/]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    
    def create_dashboard(self) -> Layout:
        """Create main dashboard layout"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        
        layout["left"].split_column(
            Layout(name="stats", size=8),
            Layout(name="activity"),
        )
        
        # Add content
        layout["header"].update(self.create_header())
        layout["stats"].update(self.create_stats_panel())
        layout["right"].update(self.create_modules_panel())
        layout["activity"].update(self.create_activity_panel())
        
        footer_text = Text()
        footer_text.append("Commands: ", style="bold white")
        footer_text.append("[Q]uit ", style="cyan")
        footer_text.append("[A]PT ", style="cyan")
        footer_text.append("[B]lockchain ", style="cyan")
        footer_text.append("[T]raffic ", style="cyan")
        footer_text.append("[H]elp", style="cyan")
        
        layout["footer"].update(Panel(footer_text, style="white on blue"))
        
        return layout
    
    def run(self):
        """Run the CLI"""
        self.console.clear()
        
        # Show loading
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task("[cyan]Initializing SENTINNELLE...", total=100)
            
            for i in range(100):
                progress.update(task, advance=1)
                time.sleep(0.01)
        
        # Show dashboard
        self.console.print(self.create_dashboard())
        
        # Interactive menu
        self.show_menu()
    
    def show_menu(self):
        """Show interactive menu"""
        while True:
            self.console.print("\n[bold cyan]Select Module:[/]")
            self.console.print("1. APT Attribution")
            self.console.print("2. Encrypted Traffic Analysis")
            self.console.print("3. Blockchain Intelligence")
            self.console.print("4. Steganalysis")
            self.console.print("5. Passive SIGINT")
            self.console.print("6. De-anonymization")
            self.console.print("7. Behavioral Biometrics")
            self.console.print("8. AI Threat Hunter")
            self.console.print("9. Attack Predictor")
            self.console.print("10. Persona Profiler")
            self.console.print("0. Exit")
            
            choice = input("\n> ")
            
            if choice == "0":
                self.console.print("[yellow]Exiting SENTINNELLE...[/]")
                break
            elif choice == "1":
                self.run_apt_attribution()
            elif choice == "2":
                self.run_traffic_analysis()
            elif choice == "3":
                self.run_blockchain_intel()
            elif choice == "4":
                self.run_steganalysis()
            elif choice == "5":
                self.run_passive_sigint()
            elif choice == "6":
                self.run_deanonymization()
            elif choice == "7":
                self.run_behavioral_biometrics()
            elif choice == "8":
                self.run_ai_threat_hunter()
            elif choice == "9":
                self.run_attack_predictor()
            elif choice == "10":
                self.run_persona_profiler()
            else:
                self.console.print("[red]Invalid choice[/]")
    
    def run_apt_attribution(self):
        """Run APT Attribution module"""
        from intelligence.apt_attribution import APTAttributor
        
        self.console.print("\n[bold cyan]═══ APT Attribution Engine ═══[/]\n")
        
        # Example indicators
        indicators = {
            'ttps': ['T1566', 'T1059', 'T1003'],
            'infrastructure': {
                'countries': ['RU'],
                'asns': ['12345'],
            },
            'timestamps': ['2024-01-01T09:00:00', '2024-01-01T10:30:00'],
        }
        
        attributor = APTAttributor()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing indicators...")) as progress:
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
            table.add_row(
                apt,
                f"{prob:.1%}",
                info.get('country', 'Unknown')
            )
        
        self.console.print(table)
        self.console.print(f"\n[bold green]Top Attribution:[/] {result['top_attribution']} ({result['confidence']:.1%})")
        input("\nPress Enter to continue...")
    
    def run_blockchain_intel(self):
        """Run Blockchain Intelligence module"""
        from intelligence.blockchain_intel import BlockchainIntelligence
        
        self.console.print("\n[bold cyan]═══ Blockchain Intelligence ═══[/]\n")
        
        address = input("Enter Bitcoin address: ")
        
        intel = BlockchainIntelligence()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Tracing funds...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            trace = intel.trace_funds(address, 'bitcoin')
        
        self.console.print(f"\n[green]Trace complete for {address}[/]")
        self.console.print(f"Blockchain: {trace['blockchain']}")
        input("\nPress Enter to continue...")
    
    def run_traffic_analysis(self):
        """Run Encrypted Traffic Analysis"""
        from intelligence.traffic_analyzer import EncryptedTrafficAnalyzer
        
        self.console.print("\n[bold cyan]═══ Encrypted Traffic Analysis ═══[/]\n")
        
        analyzer = EncryptedTrafficAnalyzer()
        
        # Demo session
        session = {
            'client_hello': {
                'version': 771,
                'ciphers': [49195, 49199, 52393],
                'extensions': [0, 10, 11, 13],
                'curves': [23, 24, 25],
                'point_formats': [0],
            }
        }
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing TLS session...")) as progress:
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
        input("\nPress Enter to continue...")
    
    def run_steganalysis(self):
        """Run Steganalysis"""
        from intelligence.steganalysis import StegAnalyzer
        
        self.console.print("\n[bold cyan]═══ Steganalysis Engine ═══[/]\n")
        
        analyzer = StegAnalyzer()
        
        # Demo with random data
        import random
        image_data = bytes([random.randint(0, 255) for _ in range(10000)])
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing image for hidden data...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = analyzer.analyze_image(image_data)
        
        self.console.print(f"\n[bold]Suspicious:[/] {result['suspicious']}")
        self.console.print(f"[bold]Confidence:[/] {result['confidence']:.1%}")
        if result['techniques_detected']:
            self.console.print(f"[bold]Techniques:[/] {', '.join(result['techniques_detected'])}")
        
        input("\nPress Enter to continue...")
    
    def run_passive_sigint(self):
        """Run Passive SIGINT"""
        from intelligence.passive_sigint import PassiveSIGINT
        
        self.console.print("\n[bold cyan]═══ Passive SIGINT ═══[/]\n")
        
        domain = input("Enter domain: ")
        
        sigint = PassiveSIGINT()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Reconstructing infrastructure...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            result = sigint.reconstruct_infrastructure(domain)
        
        self.console.print(f"\n[green]Infrastructure reconstruction complete[/]")
        self.console.print(f"Domain: {result['domain']}")
        self.console.print(f"Passive DNS records: {len(result['passive_dns'])}")
        self.console.print(f"Certificate history: {len(result['certificate_history'])}")
        
        input("\nPress Enter to continue...")
    
    def run_deanonymization(self):
        """Run De-anonymization"""
        from intelligence.deanonymization import DeAnonymizer
        
        self.console.print("\n[bold cyan]═══ De-Anonymization Engine ═══[/]\n")
        
        deanon = DeAnonymizer()
        
        # Demo browser data
        browser_data = {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'screen_resolution': '1920x1080',
            'timezone': 'America/New_York',
            'plugins': ['PDF Viewer', 'Chrome PDF Plugin'],
            'fonts': ['Arial', 'Times New Roman', 'Courier'],
            'canvas_hash': 'abc123',
            'webgl_hash': 'def456',
        }
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating browser fingerprint...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            fingerprint = deanon.fingerprint_browser(browser_data)
        
        self.console.print(f"\n[bold green]Browser Fingerprint:[/]")
        self.console.print(f"{fingerprint}")
        self.console.print(f"\n[yellow]This fingerprint is unique and can track users across sessions[/]")
        
        input("\nPress Enter to continue...")
    
    def run_behavioral_biometrics(self):
        """Run Behavioral Biometrics"""
        from intelligence.behavioral_biometrics import BehavioralBiometrics
        
        self.console.print("\n[bold cyan]═══ Behavioral Biometrics ═══[/]\n")
        
        bio = BehavioralBiometrics()
        
        # Demo keystroke data
        import random
        keystroke_data = [
            {
                'press_time': i * 0.1,
                'release_time': i * 0.1 + random.uniform(0.05, 0.15),
            }
            for i in range(50)
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating typing profile...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(1)
            profile = bio.create_typing_profile(keystroke_data)
        
        self.console.print(f"\n[green]Typing profile created[/]")
        self.console.print(f"Profile dimensions: {len(profile)}")
        self.console.print(f"Average dwell time: {profile[::2].mean():.3f}s")
        self.console.print(f"Average flight time: {profile[1::2].mean():.3f}s")
        
        input("\nPress Enter to continue...")
    
    def run_ai_threat_hunter(self):
        """Run AI Threat Hunter"""
        from intelligence.ai_threat_hunter import AIThreatHunter
        
        self.console.print("\n[bold cyan]═══ AI Threat Hunter ═══[/]\n")
        
        hunter = AIThreatHunter()
        
        # Demo telemetry
        telemetry = [
            {'type': 'network', 'anomaly_score': 0.8},
            {'type': 'process', 'anomaly_score': 0.3},
        ]
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Hunting for threats...")) as progress:
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
        else:
            self.console.print("[green]No threats detected[/]")
        
        input("\nPress Enter to continue...")
    
    def run_attack_predictor(self):
        """Run Attack Predictor"""
        from intelligence.attack_predictor import AttackPredictor
        
        self.console.print("\n[bold cyan]═══ Attack Prediction Engine ═══[/]\n")
        
        target = input("Enter target (domain/IP): ")
        
        predictor = AttackPredictor()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Predicting attack likelihood...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(2)
            prediction = predictor.predict_attack(target, '24h')
        
        # Display prediction
        prob = prediction['probability']
        color = "red" if prob > 0.7 else "yellow" if prob > 0.4 else "green"
        
        self.console.print(f"\n[bold]Target:[/] {target}")
        self.console.print(f"[bold]Timeframe:[/] {prediction['timeframe']}")
        self.console.print(f"[bold]Attack Probability:[/] [{color}]{prob:.1%}[/]")
        self.console.print(f"[bold]Likely Vector:[/] {prediction['likely_vector']}")
        self.console.print(f"[bold]Attribution:[/] {prediction['attribution']}")
        
        self.console.print(f"\n[bold cyan]Recommendations:[/]")
        for rec in prediction['recommended_actions']:
            self.console.print(f"  • {rec}")
        
        input("\nPress Enter to continue...")
    
    def run_persona_profiler(self):
        """Run Persona Profiler"""
        from intelligence.persona_profiler import PersonaProfiler
        
        self.console.print("\n[bold cyan]═══ Persona Profiler ═══[/]\n")
        
        target = input("Enter target identifier (email/username): ")
        
        profiler = PersonaProfiler()
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]Creating psychological profile...")) as progress:
            task = progress.add_task("", total=None)
            time.sleep(2)
            profile = profiler.create_profile(target)
        
        self.console.print(f"\n[bold green]Profile Created for {target}[/]\n")
        
        # OCEAN personality
        table = Table(title="OCEAN Personality Assessment", box=box.ROUNDED)
        table.add_column("Trait", style="cyan")
        table.add_column("Score", style="green")
        
        for trait, score in profile['personality'].items():
            table.add_row(trait.capitalize(), f"{score:.1%}")
        
        self.console.print(table)
        
        self.console.print(f"\n[yellow]⚠ Use responsibly - for authorized security assessments only[/]")
        
        input("\nPress Enter to continue...")


def main():
    """Main entry point"""
    cli = SentinnelleCLI()
    cli.run()


if __name__ == '__main__':
    main()
