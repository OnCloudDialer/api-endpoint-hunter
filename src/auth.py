"""Authentication handlers for different auth methods."""

from __future__ import annotations

import asyncio
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import Page, BrowserContext
from rich.console import Console

from .models import CrawlConfig

console = Console()


class AuthHandler:
    """Handles various authentication methods."""
    
    def __init__(self, config: CrawlConfig):
        self.config = config
    
    async def setup_auth(self, context: BrowserContext, page: Page) -> bool:
        """Set up authentication based on config. Returns True if successful."""
        
        success = True
        
        # Set up cookies if provided
        if self.config.cookies:
            await self._set_cookies(context)
        
        # Set up auth headers if provided
        if self.config.auth_headers:
            await self._set_headers(context)
        
        # Perform form login if credentials provided
        if self.config.login_url and self.config.username and self.config.password:
            success = await self._perform_login(page)
        
        return success
    
    async def _set_cookies(self, context: BrowserContext):
        """Set cookies on the browser context."""
        parsed = urlparse(self.config.start_url)
        domain = parsed.netloc
        
        # Remove port from domain if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        cookies = []
        for name, value in self.config.cookies.items():
            cookies.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
            })
        
        if cookies:
            await context.add_cookies(cookies)
            console.print(f"[green]✓[/] Set {len(cookies)} cookie(s)")
    
    async def _set_headers(self, context: BrowserContext):
        """Set extra HTTP headers for all requests."""
        await context.set_extra_http_headers(self.config.auth_headers)
        console.print(f"[green]✓[/] Set {len(self.config.auth_headers)} auth header(s)")
    
    async def _perform_login(self, page: Page) -> bool:
        """Perform form-based login."""
        console.print(f"\n[bold cyan]🔐 Performing login...[/]")
        console.print(f"  [dim]Login URL: {self.config.login_url}[/]")
        
        try:
            # Navigate to login page
            await page.goto(self.config.login_url, wait_until="networkidle")
            await asyncio.sleep(1)  # Wait for any JS to initialize
            
            # Find username field
            username_selector = self.config.username_field or await self._find_username_field(page)
            if not username_selector:
                console.print("[red]✗[/] Could not find username field")
                return False
            
            # Find password field
            password_selector = self.config.password_field or await self._find_password_field(page)
            if not password_selector:
                console.print("[red]✗[/] Could not find password field")
                return False
            
            console.print(f"  [dim]Username field: {username_selector}[/]")
            console.print(f"  [dim]Password field: {password_selector}[/]")
            
            # Fill in credentials
            await page.fill(username_selector, self.config.username)
            await page.fill(password_selector, self.config.password)
            
            # Find and click submit button
            submit_selector = await self._find_submit_button(page)
            if submit_selector:
                console.print(f"  [dim]Submit button: {submit_selector}[/]")
                await page.click(submit_selector)
            else:
                # Try pressing Enter
                console.print("  [dim]No submit button found, pressing Enter[/]")
                await page.press(password_selector, "Enter")
            
            # Wait for navigation/response
            await asyncio.sleep(2)
            
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass  # May timeout if already idle
            
            # Check if login was successful by looking for common indicators
            current_url = page.url
            login_url_parsed = urlparse(self.config.login_url)
            current_url_parsed = urlparse(current_url)
            
            # If we're no longer on the login page, likely successful
            if current_url_parsed.path != login_url_parsed.path:
                console.print("[green]✓[/] Login appears successful (redirected)")
                return True
            
            # Check for common error indicators
            error_selectors = [
                ".error", ".alert-danger", ".login-error", 
                "[class*='error']", "[class*='invalid']",
                "#error", "#login-error"
            ]
            
            for selector in error_selectors:
                try:
                    error_elem = await page.query_selector(selector)
                    if error_elem:
                        is_visible = await error_elem.is_visible()
                        if is_visible:
                            text = await error_elem.text_content()
                            if text and text.strip():
                                console.print(f"[red]✗[/] Login error: {text.strip()[:100]}")
                                return False
                except Exception:
                    pass
            
            # Check for logged-in indicators
            logged_in_selectors = [
                "[class*='logout']", "[class*='signout']",
                "[href*='logout']", "[href*='signout']",
                ".user-menu", ".profile-menu", ".account-menu",
            ]
            
            for selector in logged_in_selectors:
                try:
                    elem = await page.query_selector(selector)
                    if elem:
                        console.print("[green]✓[/] Login successful (found logged-in indicator)")
                        return True
                except Exception:
                    pass
            
            console.print("[yellow]?[/] Login status unclear, continuing anyway")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/] Login failed: {str(e)}")
            return False
    
    async def _find_username_field(self, page: Page) -> Optional[str]:
        """Auto-detect the username/email input field."""
        selectors = [
            'input[type="email"]',
            'input[name="email"]',
            'input[name="username"]',
            'input[name="user"]',
            'input[name="login"]',
            'input[id="email"]',
            'input[id="username"]',
            'input[autocomplete="email"]',
            'input[autocomplete="username"]',
            'input[placeholder*="email" i]',
            'input[placeholder*="username" i]',
            'input[type="text"]:first-of-type',
        ]
        
        for selector in selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        return selector
            except Exception:
                pass
        
        return None
    
    async def _find_password_field(self, page: Page) -> Optional[str]:
        """Auto-detect the password input field."""
        selectors = [
            'input[type="password"]',
            'input[name="password"]',
            'input[name="pass"]',
            'input[id="password"]',
            'input[autocomplete="current-password"]',
        ]
        
        for selector in selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        return selector
            except Exception:
                pass
        
        return None
    
    async def _find_submit_button(self, page: Page) -> Optional[str]:
        """Auto-detect the login submit button."""
        selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Log in")',
            'button:has-text("Login")',
            'button:has-text("Sign in")',
            'button:has-text("Sign In")',
            'button:has-text("Submit")',
            '[class*="login"] button',
            '[class*="submit"]',
            'form button:last-of-type',
        ]
        
        for selector in selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        return selector
            except Exception:
                pass
        
        return None
