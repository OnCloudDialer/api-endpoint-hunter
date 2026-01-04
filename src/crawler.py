"""Web crawler that navigates pages and triggers API calls."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from datetime import datetime
from typing import Set
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .models import CrawlConfig, CrawlResult, CapturedEndpoint
from .interceptor import APIInterceptor
from .auth import AuthHandler

console = Console()


class Crawler:
    """Crawls websites and captures API endpoints."""
    
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.interceptor = APIInterceptor(config)
        self.auth_handler = AuthHandler(config)
        self.visited_urls: Set[str] = set()
        self.urls_to_visit: deque[tuple[str, int]] = deque()  # (url, depth)
        self.current_page_url: str = ""
        self.errors: list[str] = []
        
        # Parse base domain for same-origin filtering
        parsed = urlparse(config.start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
    
    def _is_same_origin(self, url: str) -> bool:
        """Check if URL is from the same origin."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain
        except Exception:
            return False
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment and normalize
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            # Sort query params for consistent deduplication
            params = sorted(parsed.query.split("&"))
            normalized += "?" + "&".join(params)
        return normalized.rstrip("/")
    
    def _should_visit(self, url: str) -> bool:
        """Check if URL should be visited."""
        # Must be same origin
        if not self._is_same_origin(url):
            return False
        
        # Skip certain file types
        skip_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
            ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3",
        }
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in skip_extensions:
            if path.endswith(ext):
                return False
        
        # Check if already visited
        normalized = self._normalize_url(url)
        if normalized in self.visited_urls:
            return False
        
        return True
    
    async def _extract_links(self, page: Page) -> list[str]:
        """Extract all links from the page."""
        links = []
        
        try:
            # Get href attributes from anchor tags
            anchors = await page.query_selector_all("a[href]")
            for anchor in anchors:
                try:
                    href = await anchor.get_attribute("href")
                    if href:
                        # Convert relative URLs to absolute
                        absolute_url = urljoin(page.url, href)
                        links.append(absolute_url)
                except Exception:
                    pass
            
            # Also check for data attributes that might contain links
            elements_with_routes = await page.query_selector_all("[data-href], [data-link], [data-route]")
            for elem in elements_with_routes:
                for attr in ["data-href", "data-link", "data-route"]:
                    try:
                        value = await elem.get_attribute(attr)
                        if value:
                            absolute_url = urljoin(page.url, value)
                            links.append(absolute_url)
                    except Exception:
                        pass
                        
        except Exception as e:
            self.errors.append(f"Error extracting links: {str(e)}")
        
        return links
    
    async def _interact_with_page(self, page: Page):
        """Interact with page elements to trigger API calls."""
        
        # Click on interactive elements that might trigger API calls
        interactive_selectors = [
            'button:not([type="submit"])',
            '[role="button"]',
            '[class*="expand"]',
            '[class*="toggle"]',
            '[class*="dropdown"]',
            '[class*="accordion"]',
            '[class*="tab"]:not(.active)',
            '[data-toggle]',
            '[onclick]',
        ]
        
        for selector in interactive_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for elem in elements[:3]:  # Limit to first 3 of each type
                    try:
                        is_visible = await elem.is_visible()
                        if is_visible:
                            # Check if it's in viewport
                            box = await elem.bounding_box()
                            if box and box["width"] > 0 and box["height"] > 0:
                                await elem.click(timeout=2000)
                                await asyncio.sleep(0.5)
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Scroll to trigger lazy loading
        try:
            await page.evaluate("""
                async () => {
                    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
                    const height = document.body.scrollHeight;
                    const step = window.innerHeight;
                    for (let y = 0; y < height; y += step) {
                        window.scrollTo(0, y);
                        await delay(200);
                    }
                    window.scrollTo(0, 0);
                }
            """)
        except Exception:
            pass
    
    async def _crawl_page(self, page: Page, url: str, depth: int) -> list[str]:
        """Crawl a single page and return discovered links."""
        normalized = self._normalize_url(url)
        if normalized in self.visited_urls:
            return []
        
        self.visited_urls.add(normalized)
        self.current_page_url = url
        
        console.print(f"\n[bold blue]📄 Page {len(self.visited_urls)}:[/] {url}")
        console.print(f"   [dim]Depth: {depth}[/]")
        
        try:
            # Navigate to page
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            
            if response and response.status >= 400:
                console.print(f"   [yellow]⚠ Status: {response.status}[/]")
            
            # Wait for initial content and API calls
            await asyncio.sleep(self.config.wait_time / 1000)
            
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass  # May timeout, that's ok
            
            # Interact with page to trigger more API calls
            await self._interact_with_page(page)
            
            # Wait for any triggered requests to complete
            await asyncio.sleep(1)
            
            # Extract links for further crawling
            if depth < self.config.max_depth:
                links = await self._extract_links(page)
                return [link for link in links if self._should_visit(link)]
            
            return []
            
        except Exception as e:
            error_msg = f"Error crawling {url}: {str(e)}"
            console.print(f"   [red]✗ {error_msg}[/]")
            self.errors.append(error_msg)
            return []
    
    async def crawl(self) -> CrawlResult:
        """Execute the crawl and return results."""
        result = CrawlResult(config=self.config)
        
        console.print("\n[bold magenta]╔════════════════════════════════════════╗[/]")
        console.print("[bold magenta]║[/]     [bold white]🔍 API Endpoint Hunter[/]          [bold magenta]║[/]")
        console.print("[bold magenta]╚════════════════════════════════════════╝[/]\n")
        
        console.print(f"[bold]Target:[/] {self.config.start_url}")
        console.print(f"[bold]Max Pages:[/] {self.config.max_pages}")
        console.print(f"[bold]Max Depth:[/] {self.config.max_depth}")
        
        async with async_playwright() as p:
            # Launch browser
            console.print("\n[cyan]🚀 Launching browser...[/]")
            browser = await p.chromium.launch(headless=self.config.headless)
            
            # Create context with viewport
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            
            page = await context.new_page()
            
            # Set up interceptor
            await self.interceptor.setup(page, lambda: self.current_page_url)
            
            # Handle authentication
            console.print("\n[cyan]🔐 Setting up authentication...[/]")
            auth_success = await self.auth_handler.setup_auth(context, page)
            
            if not auth_success:
                console.print("[yellow]⚠ Authentication may have failed, continuing anyway...[/]")
            
            # Start crawling
            console.print("\n[cyan]🕷️ Starting crawl...[/]")
            
            self.urls_to_visit.append((self.config.start_url, 0))
            
            while self.urls_to_visit and len(self.visited_urls) < self.config.max_pages:
                url, depth = self.urls_to_visit.popleft()
                
                if not self._should_visit(url):
                    continue
                
                new_links = await self._crawl_page(page, url, depth)
                
                # Add new links to queue
                for link in new_links:
                    if len(self.visited_urls) + len(self.urls_to_visit) < self.config.max_pages:
                        self.urls_to_visit.append((link, depth + 1))
            
            # Close browser
            await browser.close()
        
        # Compile results
        result.pages_visited = list(self.visited_urls)
        result.errors = self.errors
        result.end_time = datetime.now()
        
        # Get captured endpoints from interceptor
        captured = self.interceptor.get_captured_endpoints()
        
        console.print(f"\n[bold green]✓ Crawl complete![/]")
        console.print(f"  [dim]Pages visited: {len(self.visited_urls)}[/]")
        console.print(f"  [dim]API calls captured: {len(captured)}[/]")
        console.print(f"  [dim]Duration: {result.duration_seconds:.1f}s[/]")
        
        return result, captured
