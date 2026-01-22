from abc import ABC, abstractmethod
from typing import Any, List
from ...ui.progress_manager import get_manager, UIContext
from ....core.engine import EngineEvent, EventType, BaseEngine

class BaseTaskRunner(ABC):
    def __init__(self, console):
        self.console = console
        self.pm = get_manager(console)

    def _setup_callback(self, ctx: UIContext):
        def callback(event: EngineEvent):
            if event.type == EventType.LOG:
                ctx.log(event.message)
            elif event.type == EventType.PROGRESS:
                ctx.update_progress(**event.data)
            elif event.type == EventType.DATA:
                self.handle_data(ctx, event.data)
            elif event.type == EventType.ERROR:
                ctx.log(f"[red]Error: {event.message}[/]")
        return callback

    @abstractmethod
    def handle_data(self, ctx: UIContext, data: Any):
        """Handle engine-specific data events."""
        pass

    @abstractmethod
    def run(self):
        """Main execution flow."""
        pass
