from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
from enum import Enum, auto


class EventType(Enum):
    LOG = auto()
    PROGRESS = auto()
    DATA = auto()
    ERROR = auto()
    COMPLETE = auto()


class EngineEvent:
    def __init__(self, type: EventType, data: Any = None, message: Optional[str] = None):
        self.type = type
        self.data = data
        self.message = message


class BaseEngine(ABC):
    """Abstract base class for all intelligence engines."""
    
    def __init__(self):
        self.callbacks: List[Callable[[EngineEvent], None]] = []

    def register_callback(self, callback: Callable[[EngineEvent], None]):
        self.callbacks.append(callback)

    def emit(self, event_type: EventType, data: Any = None, message: Optional[str] = None):
        event = EngineEvent(event_type, data, message)
        for callback in self.callbacks:
            callback(event)

    def log(self, message: str):
        self.emit(EventType.LOG, message=message)

    def progress(self, advance: int = 1, description: Optional[str] = None, total: Optional[int] = None, **kwargs):
        """
        Military-grade progress reporting. 
        Supports positional-ish advance, explicit total, and arbitrary metadata.
        """
        data = {"advance": advance}
        if description is not None:
            data["description"] = description
        if total is not None:
            data["total"] = total
        
        # Merge extra metadata, ensuring no collisions with primary keys
        for k, v in kwargs.items():
            if k not in data:
                data[k] = v
                
        self.emit(EventType.PROGRESS, data=data)

    def error(self, message: str):
        self.emit(EventType.ERROR, message=message)

    async def run_search(self, target: str, on_complete: Optional[Callable[[Any], None]] = None, log_callback: Optional[Callable[[str], None]] = None, **kwargs) -> Any:
        """
        High-level search method for consistency across engines.
        Handles callback registration and delegation to run().
        """
        if log_callback:
            def _log_cb(event):
                if event.type == EventType.LOG and event.message:
                    log_callback(event.message)
            self.register_callback(_log_cb)

        if on_complete:
            def _data_cb(event):
                if event.type == EventType.DATA:
                    on_complete(event.data)
            self.register_callback(_data_cb)

        return await self.run(target, **kwargs)

    @abstractmethod
    async def run(self, target: str, **kwargs) -> Any:
        """Execute the engine's main logic."""
        pass
