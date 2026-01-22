import logging
from typing import Optional

from .runners.email import EmailTaskRunner
from .runners.phone import PhoneTaskRunner
from .runners.ip import IPTaskRunner
from .runners.social import SocialTaskRunner
from .runners.domain import DomainTaskRunner
from .runners.network import NetworkTaskRunner

class ModuleRunner:
    """
    Unified module runner for Sentinelle.
    Acts as a facade for specialized TaskRunners.
    """
    
    def __init__(self, console):
        self.console = console
        self.logger = logging.getLogger("sentinelle")

    def _run_task(self, runner_class):
        """Generic execution helper for TaskRunners."""
        try:
            runner = runner_class(self.console)
            runner.run()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Interrupted by user[/]")
        except Exception as e:
            self.logger.exception(f"Error executing {runner_class.__name__}")
            self.console.print(f"[red]Error: {str(e)}[/]")
            input("\nPress Enter to continue...")

    def run_email_osint(self):
        """Standardized Email OSINT runner."""
        self._run_task(EmailTaskRunner)

    def run_phone_collector(self):
        """Standardized Phone Intelligence runner."""
        self._run_task(PhoneTaskRunner)

    def run_ip_collector(self):
        """Standardized IP Intelligence runner."""
        self._run_task(IPTaskRunner)

    def run_social_engine(self):
        """Standardized Social Media Search runner."""
        self._run_task(SocialTaskRunner)

    def run_domain_collector(self):
        """Standardized Domain OSINT runner."""
        self._run_task(DomainTaskRunner)

    def run_network_sigint(self):
        """Standardized Network SIGINT runner."""
        self._run_task(NetworkTaskRunner)
