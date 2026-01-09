import os
import random
from rich.panel import Panel
from rich.text import Text
from rich import box
from datetime import datetime
from ...core.config import UIConfig

def get_random_banner() -> str:
    """Select a random banner different from the last one"""
    banners = UIConfig.BANNERS
    cache_dir = os.path.join(os.getcwd(), ".cache")
    cache_file = os.path.join(cache_dir, "last_banner_idx")
    
    # Ensure cache exists
    os.makedirs(cache_dir, exist_ok=True)
    
    last_idx = -1
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                last_idx = int(f.read().strip())
        except (ValueError, IOError):
            pass
    
    # Select new index
    available_indices = [i for i in range(len(banners)) if i != last_idx]
    if not available_indices: # Should not happen unless only 1 banner
        available_indices = [0]
        
    new_idx = random.choice(available_indices)
    
    # Save new index
    try:
        with open(cache_file, "w") as f:
            f.write(str(new_idx))
    except IOError:
        pass
        
    return banners[new_idx]

def create_header() -> Panel:
    """Create header panel"""
    banner = get_random_banner()
    header_text = Text(banner, style="bold cyan", no_wrap=True)
    header_text.append("\n" + UIConfig.APP_SUBTITLE, style="bold green")
    header_text.append(" | ", style="white")
    header_text.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="yellow")
    
    return Panel(
        header_text,
        box=box.DOUBLE,
        style=UIConfig.HEADER_STYLE,
        title="[bold white]NSA/UNIT 8200 COMPLIANT[/]",
        subtitle="[bold white]v2.0-Elite[/]",
    )
