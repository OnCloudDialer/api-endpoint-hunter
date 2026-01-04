"""Configuration manager for saving and loading crawl profiles."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

from rich.console import Console
from rich.table import Table

from .models import CrawlConfig

console = Console()

# Default config directory
CONFIG_DIR = Path.home() / ".api-endpoint-hunter" / "profiles"


def get_config_dir() -> Path:
    """Get the configuration directory, creating it if needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def get_profile_path(name: str) -> Path:
    """Get the path for a profile by name."""
    # Sanitize name for filesystem
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return get_config_dir() / f"{safe_name}.json"


def save_profile(name: str, config: CrawlConfig, description: str = "") -> Path:
    """Save a configuration profile."""
    profile_path = get_profile_path(name)
    
    # Convert config to dict, excluding sensitive defaults
    config_dict = {
        "name": name,
        "description": description,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "config": {
            "start_url": config.start_url,
            "login_url": config.login_url,
            "username": config.username,
            "password": config.password,  # Note: stored in plain text locally
            "username_field": config.username_field,
            "password_field": config.password_field,
            "auth_headers": config.auth_headers,
            "cookies": config.cookies,
            "max_pages": config.max_pages,
            "max_depth": config.max_depth,
            "wait_time": config.wait_time,
            "headless": config.headless,
            "output_dir": config.output_dir,
            "output_format": config.output_format,
            "include_patterns": config.include_patterns,
            "exclude_patterns": config.exclude_patterns,
        }
    }
    
    with open(profile_path, "w") as f:
        json.dump(config_dict, f, indent=2)
    
    console.print(f"[green]✓[/] Profile saved: [bold]{name}[/]")
    console.print(f"  [dim]Location: {profile_path}[/]")
    
    return profile_path


def load_profile(name: str) -> Optional[CrawlConfig]:
    """Load a configuration profile by name."""
    profile_path = get_profile_path(name)
    
    if not profile_path.exists():
        console.print(f"[red]✗[/] Profile not found: [bold]{name}[/]")
        return None
    
    try:
        with open(profile_path, "r") as f:
            data = json.load(f)
        
        config_data = data.get("config", {})
        config = CrawlConfig(**config_data)
        
        console.print(f"[green]✓[/] Profile loaded: [bold]{name}[/]")
        if data.get("description"):
            console.print(f"  [dim]{data['description']}[/]")
        
        return config
        
    except Exception as e:
        console.print(f"[red]✗[/] Error loading profile: {str(e)}")
        return None


def list_profiles() -> list[dict]:
    """List all saved profiles."""
    config_dir = get_config_dir()
    profiles = []
    
    for file_path in config_dir.glob("*.json"):
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
            
            profiles.append({
                "name": data.get("name", file_path.stem),
                "description": data.get("description", ""),
                "url": data.get("config", {}).get("start_url", ""),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
                "has_auth": bool(
                    data.get("config", {}).get("username") or 
                    data.get("config", {}).get("auth_headers") or
                    data.get("config", {}).get("cookies")
                ),
            })
        except Exception:
            pass
    
    return sorted(profiles, key=lambda x: x.get("updated_at", ""), reverse=True)


def delete_profile(name: str) -> bool:
    """Delete a configuration profile."""
    profile_path = get_profile_path(name)
    
    if not profile_path.exists():
        console.print(f"[red]✗[/] Profile not found: [bold]{name}[/]")
        return False
    
    try:
        profile_path.unlink()
        console.print(f"[green]✓[/] Profile deleted: [bold]{name}[/]")
        return True
    except Exception as e:
        console.print(f"[red]✗[/] Error deleting profile: {str(e)}")
        return False


def display_profiles():
    """Display all profiles in a nice table."""
    profiles = list_profiles()
    
    if not profiles:
        console.print("[dim]No saved profiles found.[/]")
        console.print("[dim]Use --save-as to save a configuration.[/]")
        return
    
    table = Table(
        title="📁 Saved Profiles",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    
    table.add_column("Name", style="bold")
    table.add_column("URL", style="cyan")
    table.add_column("Auth", justify="center")
    table.add_column("Description", style="dim")
    
    for profile in profiles:
        auth_icon = "🔐" if profile["has_auth"] else "—"
        url = profile["url"]
        if len(url) > 40:
            url = url[:37] + "..."
        
        table.add_row(
            profile["name"],
            url,
            auth_icon,
            profile["description"][:30] + "..." if len(profile.get("description", "")) > 30 else profile.get("description", ""),
        )
    
    console.print(table)
    console.print(f"\n[dim]Total: {len(profiles)} profile(s)[/]")


def export_profile(name: str, output_path: str) -> bool:
    """Export a profile to a specific location."""
    profile_path = get_profile_path(name)
    
    if not profile_path.exists():
        console.print(f"[red]✗[/] Profile not found: [bold]{name}[/]")
        return False
    
    try:
        import shutil
        shutil.copy(profile_path, output_path)
        console.print(f"[green]✓[/] Profile exported to: [bold]{output_path}[/]")
        return True
    except Exception as e:
        console.print(f"[red]✗[/] Error exporting profile: {str(e)}")
        return False


def import_profile(file_path: str, name: Optional[str] = None) -> bool:
    """Import a profile from a file."""
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        
        # Use provided name or name from file
        profile_name = name or data.get("name", Path(file_path).stem)
        
        # Save to profiles directory
        dest_path = get_profile_path(profile_name)
        
        # Update name in data
        data["name"] = profile_name
        data["updated_at"] = datetime.now().isoformat()
        
        with open(dest_path, "w") as f:
            json.dump(data, f, indent=2)
        
        console.print(f"[green]✓[/] Profile imported: [bold]{profile_name}[/]")
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/] Error importing profile: {str(e)}")
        return False
