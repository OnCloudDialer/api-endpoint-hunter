#!/usr/bin/env python3
"""
🔍 API Endpoint Hunter

A powerful tool that crawls websites, intercepts API calls,
and automatically generates comprehensive API documentation.

Usage:
    python hunter.py crawl https://example.com
    python hunter.py crawl https://example.com --login-url https://example.com/login --username user --password pass
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.models import CrawlConfig
from src.crawler import Crawler
from src.analyzer import EndpointAnalyzer
from src.generator import (
    DocumentationWriter,
    MarkdownGenerator,
    OpenAPIGenerator,
)

# Initialize CLI app
app = typer.Typer(
    name="hunter",
    help="🔍 API Endpoint Hunter - Crawl websites and generate API documentation",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def parse_header(header: str) -> tuple[str, str]:
    """Parse header string in format 'Name: Value'."""
    if ":" not in header:
        raise typer.BadParameter(f"Invalid header format: {header}. Expected 'Name: Value'")
    name, value = header.split(":", 1)
    return name.strip(), value.strip()


def parse_cookie(cookie: str) -> tuple[str, str]:
    """Parse cookie string in format 'name=value'."""
    if "=" not in cookie:
        raise typer.BadParameter(f"Invalid cookie format: {cookie}. Expected 'name=value'")
    name, value = cookie.split("=", 1)
    return name.strip(), value.strip()


@app.command()
def crawl(
    url: str = typer.Argument(..., help="The starting URL to crawl"),
    
    # Authentication options
    login_url: Optional[str] = typer.Option(
        None, "--login-url", "-l",
        help="URL of the login page for form-based authentication"
    ),
    username: Optional[str] = typer.Option(
        None, "--username", "-u",
        help="Username for form-based login"
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="Password for form-based login"
    ),
    username_field: Optional[str] = typer.Option(
        None, "--username-field",
        help="CSS selector for username input (auto-detected if not specified)"
    ),
    password_field: Optional[str] = typer.Option(
        None, "--password-field",
        help="CSS selector for password input (auto-detected if not specified)"
    ),
    auth_header: Optional[List[str]] = typer.Option(
        None, "--auth-header", "-H",
        help="Auth header in format 'Name: Value' (can be repeated)"
    ),
    cookie: Optional[List[str]] = typer.Option(
        None, "--cookie", "-c",
        help="Cookie in format 'name=value' (can be repeated)"
    ),
    
    # Crawl options
    max_pages: int = typer.Option(
        50, "--max-pages", "-n",
        help="Maximum number of pages to crawl"
    ),
    max_depth: int = typer.Option(
        3, "--max-depth", "-d",
        help="Maximum link depth to follow"
    ),
    wait_time: int = typer.Option(
        2000, "--wait-time", "-w",
        help="Time to wait after page load (milliseconds)"
    ),
    
    # Output options
    output: str = typer.Option(
        "./api-docs", "--output", "-o",
        help="Output directory for documentation"
    ),
    format: str = typer.Option(
        "both", "--format", "-f",
        help="Output format: openapi, markdown, or both"
    ),
    
    # Browser options
    headless: bool = typer.Option(
        True, "--headless/--no-headless",
        help="Run browser in headless mode"
    ),
    
    # Filtering
    include: Optional[List[str]] = typer.Option(
        None, "--include", "-i",
        help="Regex pattern for URLs to include (can be repeated)"
    ),
    exclude: Optional[List[str]] = typer.Option(
        None, "--exclude", "-e",
        help="Regex pattern for URLs to exclude (can be repeated)"
    ),
):
    """
    🕷️ Crawl a website and capture all API endpoints.
    
    This command will:
    
    1. Navigate through the website following links
    2. Intercept all API calls (XHR/Fetch requests)
    3. Analyze request/response patterns
    4. Generate comprehensive API documentation
    
    Examples:
    
        Basic crawl:
        $ python hunter.py crawl https://example.com
        
        With form login:
        $ python hunter.py crawl https://app.example.com \\
            --login-url https://app.example.com/login \\
            --username admin@example.com \\
            --password secret
        
        With bearer token:
        $ python hunter.py crawl https://api.example.com \\
            --auth-header "Authorization: Bearer eyJhbG..."
        
        With cookies:
        $ python hunter.py crawl https://dashboard.example.com \\
            --cookie "session=abc123" \\
            --cookie "auth=xyz789"
    """
    
    # Parse headers
    auth_headers = {}
    if auth_header:
        for h in auth_header:
            name, value = parse_header(h)
            auth_headers[name] = value
    
    # Parse cookies
    cookies = {}
    if cookie:
        for c in cookie:
            name, value = parse_cookie(c)
            cookies[name] = value
    
    # Build config
    config = CrawlConfig(
        start_url=url,
        login_url=login_url,
        username=username,
        password=password,
        username_field=username_field,
        password_field=password_field,
        auth_headers=auth_headers,
        cookies=cookies,
        max_pages=max_pages,
        max_depth=max_depth,
        wait_time=wait_time,
        headless=headless,
        output_dir=output,
        output_format=format,
        include_patterns=list(include) if include else [],
        exclude_patterns=list(exclude) if exclude else [
            r".*\.(png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|eot)(\?.*)?$",
            r".*/sockjs-node/.*",
            r".*/hot-update\.json$",
            r".*/__webpack_hmr.*",
            r".*/favicon\.ico$",
        ],
    )
    
    # Run the crawler
    asyncio.run(run_crawl(config))


async def run_crawl(config: CrawlConfig):
    """Execute the crawl and generate documentation."""
    
    try:
        # Create and run crawler
        crawler = Crawler(config)
        result, captured_endpoints = await crawler.crawl()
        
        if not captured_endpoints:
            console.print("\n[yellow]⚠ No API endpoints were captured.[/]")
            console.print("[dim]This could mean:[/]")
            console.print("[dim]  - The site doesn't make API calls[/]")
            console.print("[dim]  - API calls use different patterns[/]")
            console.print("[dim]  - Authentication failed[/]")
            console.print("[dim]  - Try with --no-headless to watch the crawl[/]")
            return
        
        # Analyze endpoints
        analyzer = EndpointAnalyzer()
        endpoint_groups = analyzer.analyze(captured_endpoints)
        
        if not endpoint_groups:
            console.print("\n[yellow]⚠ No unique endpoint patterns found.[/]")
            return
        
        # Display summary
        display_summary(endpoint_groups)
        
        # Generate documentation
        console.print("\n[cyan]📝 Generating documentation...[/]")
        
        writer = DocumentationWriter(config.output_dir)
        
        if config.output_format in ("openapi", "both"):
            openapi_gen = OpenAPIGenerator()
            spec = openapi_gen.generate(endpoint_groups, config)
            writer.write_openapi(spec)
        
        if config.output_format in ("markdown", "both"):
            md_gen = MarkdownGenerator()
            markdown = md_gen.generate(endpoint_groups, config)
            writer.write_markdown(markdown)
        
        # Always write raw data
        writer.write_raw_endpoints(endpoint_groups)
        
        # Final summary
        console.print("\n[bold green]✨ Documentation generated successfully![/]")
        console.print(f"[dim]Output directory: {os.path.abspath(config.output_dir)}[/]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Crawl interrupted by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/]")
        raise


def display_summary(endpoints: list):
    """Display a summary of discovered endpoints."""
    
    console.print("\n")
    
    # Summary panel
    summary_text = Text()
    summary_text.append("📊 ", style="bold")
    summary_text.append("Discovered Endpoints\n\n", style="bold cyan")
    summary_text.append(f"Total unique patterns: ", style="dim")
    summary_text.append(f"{len(endpoints)}\n", style="bold green")
    
    # Count by method
    method_counts = {}
    for ep in endpoints:
        method = ep.method.value
        method_counts[method] = method_counts.get(method, 0) + 1
    
    summary_text.append("\nBy method:\n", style="dim")
    for method, count in sorted(method_counts.items()):
        color = {
            "GET": "green",
            "POST": "blue",
            "PUT": "yellow",
            "PATCH": "magenta",
            "DELETE": "red",
        }.get(method, "white")
        summary_text.append(f"  {method}: ", style=f"bold {color}")
        summary_text.append(f"{count}\n", style="dim")
    
    console.print(Panel(summary_text, border_style="cyan"))
    
    # Endpoint table
    table = Table(
        title="Discovered API Endpoints",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    
    table.add_column("Method", style="bold", width=8)
    table.add_column("Path", style="cyan")
    table.add_column("Summary", style="dim")
    table.add_column("Captured", justify="right", style="green")
    
    for ep in endpoints[:25]:  # Show first 25
        method_color = {
            "GET": "green",
            "POST": "blue",
            "PUT": "yellow",
            "PATCH": "magenta",
            "DELETE": "red",
        }.get(ep.method.value, "white")
        
        table.add_row(
            f"[{method_color}]{ep.method.value}[/]",
            ep.path_pattern,
            ep.summary[:40] + "..." if len(ep.summary) > 40 else ep.summary,
            str(len(ep.captured)),
        )
    
    if len(endpoints) > 25:
        table.add_row("...", f"... and {len(endpoints) - 25} more", "", "")
    
    console.print(table)


@app.command()
def version():
    """Show version information."""
    console.print(Panel(
        "[bold cyan]🔍 API Endpoint Hunter[/]\n\n"
        "Version: [bold]1.0.0[/]\n"
        "Python: [bold]3.10+[/]\n"
        "Powered by: [bold]Playwright, Rich, Typer[/]",
        title="About",
        border_style="cyan",
    ))


if __name__ == "__main__":
    app()
