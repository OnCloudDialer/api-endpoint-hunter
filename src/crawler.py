"""Web crawler that navigates pages and triggers API calls."""

from __future__ import annotations

import asyncio
import os
import re
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Set, Callable, Optional
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .models import CrawlConfig, CrawlResult, CapturedEndpoint
from .interceptor import APIInterceptor
from .auth import AuthHandler

console = Console()

# Callback type for snapshot notifications
SnapshotCallback = Callable[[str, str, int], None]  # (screenshot_path, url, page_num)


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
        self.snapshots: list[dict] = []  # List of {path, url, page_num, timestamp}
        self.snapshot_callback: Optional[SnapshotCallback] = None
        
        # Create snapshots directory
        self.snapshots_dir = Path(config.output_dir) / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        
        # Parse base domain for same-origin filtering
        parsed = urlparse(config.start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
    
    def set_snapshot_callback(self, callback: SnapshotCallback):
        """Set callback to be notified when snapshots are taken."""
        self.snapshot_callback = callback
    
    async def _take_snapshot(self, page: Page, label: str = "") -> str:
        """Take a screenshot of the current page state."""
        page_num = len(self.visited_urls)
        timestamp = datetime.now().strftime("%H%M%S")
        safe_label = re.sub(r'[^\w\-]', '_', label)[:30] if label else ""
        filename = f"page_{page_num:03d}_{timestamp}_{safe_label}.png"
        filepath = self.snapshots_dir / filename
        
        try:
            await page.screenshot(path=str(filepath), full_page=False)
            
            snapshot_info = {
                "path": str(filepath),
                "filename": filename,
                "url": page.url,
                "page_num": page_num,
                "label": label,
                "timestamp": datetime.now().isoformat(),
            }
            self.snapshots.append(snapshot_info)
            
            console.print(f"   [dim magenta]📸 Snapshot: {filename}[/]")
            
            # Notify callback if set
            if self.snapshot_callback:
                self.snapshot_callback(str(filepath), page.url, page_num)
            
            return str(filepath)
        except Exception as e:
            console.print(f"   [dim red]⚠ Snapshot failed: {e}[/]")
            return ""
    
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
        
        # Track API count before interactions to see what triggers APIs
        initial_api_count = len(self.interceptor.captured_endpoints)
        
        # 1. Click on LIST ITEMS - these often trigger detail API calls
        list_item_selectors = [
            # Table rows (common in admin panels, dashboards)
            'table tbody tr',
            'tr[data-id]', 'tr[data-row]', 'tr[onclick]',
            # List items
            'li[onclick]', 'li[data-id]', '.list-item', '.list-group-item',
            # Cards (often clickable in modern UIs)
            '.card[onclick]', '[class*="card"][data-id]', '.card-body[onclick]',
            # Generic clickable items
            '[data-id][onclick]', '[data-item]', '[data-record]',
            # Links that look like list items
            'a.list-item', 'a[class*="item"]',
        ]
        
        clicked_items = set()  # Track what we've clicked to avoid duplicates
        
        for selector in list_item_selectors:
            try:
                elements = await page.query_selector_all(selector)
                # Click first item, then check if 2nd item gives same API
                items_to_click = elements[:2]  # First 2 items
                
                for i, elem in enumerate(items_to_click):
                    try:
                        is_visible = await elem.is_visible()
                        if not is_visible:
                            continue
                        
                        box = await elem.bounding_box()
                        if not box or box["width"] <= 0 or box["height"] <= 0:
                            continue
                        
                        # Get some identifier for this element
                        elem_text = await elem.inner_text()
                        elem_id = elem_text[:50] if elem_text else f"elem_{i}"
                        
                        if elem_id in clicked_items:
                            continue
                        clicked_items.add(elem_id)
                        
                        # Count APIs before click
                        apis_before = len(self.interceptor.captured_endpoints)
                        
                        console.print(f"   [dim cyan]🖱️ Clicking: {elem_id[:40]}...[/]")
                        await elem.click(timeout=3000)
                        await asyncio.sleep(1)  # Wait for API response
                        
                        # Count APIs after click
                        apis_after = len(self.interceptor.captured_endpoints)
                        if apis_after > apis_before:
                            console.print(f"   [dim green]   ✓ Triggered {apis_after - apis_before} API call(s)[/]")
                            # Take snapshot after successful API trigger
                            await self._take_snapshot(page, f"after_click_{elem_id[:20]}")
                        
                        # Go back if we navigated away
                        if page.url != self.current_page_url:
                            await page.go_back(timeout=5000)
                            await asyncio.sleep(0.5)
                        
                    except Exception as e:
                        pass  # Silent fail, continue to next element
            except Exception:
                pass
        
        # 2. Click on BUTTONS and INTERACTIVE ELEMENTS
        interactive_selectors = [
            'button:not([type="submit"])',
            '[role="button"]',
            '[class*="expand"]', '[class*="toggle"]',
            '[class*="dropdown"]', '[class*="accordion"]',
            '[class*="tab"]:not(.active)',
            '[data-toggle]', '[onclick]',
            # More specific triggers
            '[class*="view"]', '[class*="detail"]', '[class*="open"]',
            '[class*="edit"]', '[class*="show"]',
        ]
        
        for selector in interactive_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for elem in elements[:2]:  # Limit to first 2
                    try:
                        is_visible = await elem.is_visible()
                        if is_visible:
                            box = await elem.bounding_box()
                            if box and box["width"] > 0 and box["height"] > 0:
                                await elem.click(timeout=2000)
                                await asyncio.sleep(0.5)
                    except Exception:
                        pass
            except Exception:
                pass
        
        # 3. Scroll to trigger LAZY LOADING
        try:
            await page.evaluate("""
                async () => {
                    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
                    const height = document.body.scrollHeight;
                    const step = window.innerHeight;
                    for (let y = 0; y < height; y += step) {
                        window.scrollTo(0, y);
                        await delay(300);
                    }
                    window.scrollTo(0, 0);
                }
            """)
            await asyncio.sleep(0.5)
        except Exception:
            pass
        
        # Log interaction results
        final_api_count = len(self.interceptor.captured_endpoints)
        if final_api_count > initial_api_count:
            console.print(f"   [bold green]→ Interactions triggered {final_api_count - initial_api_count} new API call(s)[/]")
    
    async def _crawl_page(self, page: Page, url: str, depth: int) -> list[str]:
        """Crawl a single page and return discovered links."""
        normalized = self._normalize_url(url)
        if normalized in self.visited_urls:
            return []
        
        self.visited_urls.add(normalized)
        self.current_page_url = url
        
        console.print(f"\n[bold blue]📄 Page {len(self.visited_urls)}:[/] {url}")
        console.print(f"   [dim]Depth: {depth}/{self.config.max_depth}[/]")
        
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
            
            # Take snapshot of the page
            await self._take_snapshot(page, "initial")
            
            # Interact with page to trigger more API calls
            await self._interact_with_page(page)
            
            # Take snapshot after interactions
            await self._take_snapshot(page, "after_interactions")
            
            # Wait for any triggered requests to complete
            await asyncio.sleep(1)
            
            # Extract links for further crawling
            if depth < self.config.max_depth:
                links = await self._extract_links(page)
                valid_links = [link for link in links if self._should_visit(link)]
                console.print(f"   [dim]Found {len(valid_links)} links to follow[/]")
                return valid_links
            else:
                console.print(f"   [dim yellow]Max depth reached, not following links[/]")
            
            return []
            
        except Exception as e:
            error_msg = f"Error crawling {url}: {str(e)}"
            console.print(f"   [red]✗ {error_msg}[/]")
            self.errors.append(error_msg)
            # Try to take error snapshot
            try:
                await self._take_snapshot(page, "error")
            except:
                pass
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
        console.print(f"  [dim]Snapshots taken: {len(self.snapshots)}[/]")
        console.print(f"  [dim]Duration: {result.duration_seconds:.1f}s[/]")
        
        # Save snapshot index
        if self.snapshots:
            import json
            index_path = self.snapshots_dir / "index.json"
            with open(index_path, "w") as f:
                json.dump(self.snapshots, f, indent=2)
            console.print(f"  [dim]Snapshots saved to: {self.snapshots_dir}[/]")
        
        return result, captured
