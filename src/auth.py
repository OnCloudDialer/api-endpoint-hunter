"""Authentication handlers for different auth methods."""

from __future__ import annotations

import asyncio
from typing import Optional, Callable, Awaitable
from urllib.parse import urlparse

from playwright.async_api import Page, BrowserContext
from rich.console import Console
from rich.prompt import Prompt

from .models import CrawlConfig

console = Console()

# Callback for 2FA code input (can be overridden by web interface)
_2fa_callback: Optional[Callable[[str], Awaitable[str]]] = None


def set_2fa_callback(callback: Optional[Callable[[str], Awaitable[str]]]):
    """Set a custom callback for 2FA code input (used by web interface)."""
    global _2fa_callback
    _2fa_callback = callback


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
            
            # Check for 2FA/MFA prompt
            is_2fa = await self._check_for_2fa(page)
            if is_2fa:
                console.print("[yellow]🔐 Two-factor authentication detected![/]")
                success = await self._handle_2fa(page)
                if not success:
                    console.print("[red]✗[/] 2FA verification failed")
                    return False
                console.print("[green]✓[/] 2FA verification successful")
                
                # Wait for redirect after 2FA
                await asyncio.sleep(2)
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
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
    
    async def _check_for_2fa(self, page: Page) -> bool:
        """Check if the page is showing a 2FA/MFA prompt."""
        # Common 2FA indicators
        twofa_selectors = [
            # Input fields for codes
            'input[name*="otp"]',
            'input[name*="totp"]',
            'input[name*="2fa"]',
            'input[name*="mfa"]',
            'input[name*="code"]',
            'input[name*="token"]',
            'input[name*="verification"]',
            'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"][maxlength="6"]',
            'input[pattern="[0-9]*"][maxlength="6"]',
            
            # Common class patterns
            '[class*="two-factor"]',
            '[class*="2fa"]',
            '[class*="mfa"]',
            '[class*="otp"]',
            '[class*="verification-code"]',
            '[class*="authenticator"]',
        ]
        
        for selector in twofa_selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        return True
            except Exception:
                pass
        
        # Check page content for 2FA keywords
        try:
            content = await page.content()
            content_lower = content.lower()
            twofa_keywords = [
                "two-factor", "two factor", "2-factor", "2fa",
                "multi-factor", "mfa", "verification code",
                "authenticator", "security code", "one-time",
                "enter the code", "enter code", "6-digit",
                "sent to your", "check your email", "check your phone",
            ]
            
            for keyword in twofa_keywords:
                if keyword in content_lower:
                    # Double check there's an input field
                    inputs = await page.query_selector_all('input[type="text"], input[type="tel"], input[type="number"]')
                    for inp in inputs:
                        is_visible = await inp.is_visible()
                        if is_visible:
                            return True
        except Exception:
            pass
        
        return False
    
    async def _find_2fa_input(self, page: Page) -> Optional[str]:
        """Find the 2FA code input field."""
        selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name*="otp"]',
            'input[name*="totp"]',
            'input[name*="2fa"]',
            'input[name*="mfa"]',
            'input[name*="code"]',
            'input[name*="token"]',
            'input[name*="verification"]',
            'input[inputmode="numeric"]',
            'input[maxlength="6"]',
            'input[type="tel"]',
            'input[type="number"]',
            'input[type="text"]',
        ]
        
        for selector in selectors:
            try:
                elems = await page.query_selector_all(selector)
                for elem in elems:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        # Get more specific selector
                        elem_id = await elem.get_attribute("id")
                        elem_name = await elem.get_attribute("name")
                        if elem_id:
                            return f'#{elem_id}'
                        elif elem_name:
                            return f'input[name="{elem_name}"]'
                        return selector
            except Exception:
                pass
        
        return None
    
    async def _handle_2fa(self, page: Page, max_attempts: int = 3) -> bool:
        """Handle 2FA code entry."""
        global _2fa_callback
        
        input_selector = await self._find_2fa_input(page)
        if not input_selector:
            console.print("[red]✗[/] Could not find 2FA input field")
            return False
        
        console.print(f"  [dim]2FA input field: {input_selector}[/]")
        
        for attempt in range(max_attempts):
            # Get the 2FA code
            if _2fa_callback:
                # Use callback (web interface)
                console.print("[cyan]Waiting for 2FA code from interface...[/]")
                code = await _2fa_callback("Enter your 2FA code")
            else:
                # Use CLI prompt
                console.print("\n[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
                console.print("[bold yellow]  🔐 Two-Factor Authentication Required[/]")
                console.print("[bold yellow]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
                console.print("[dim]Check your authenticator app, SMS, or email[/]")
                code = Prompt.ask("\n[bold cyan]Enter 2FA code[/]")
            
            if not code or not code.strip():
                console.print("[yellow]⚠ No code entered[/]")
                continue
            
            code = code.strip()
            
            # Enter the code
            try:
                await page.fill(input_selector, code)
                await asyncio.sleep(0.5)
                
                # Try to submit
                submit_selector = await self._find_2fa_submit(page)
                if submit_selector:
                    await page.click(submit_selector)
                else:
                    await page.press(input_selector, "Enter")
                
                # Wait for response
                await asyncio.sleep(2)
                
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                
                # Check if still on 2FA page
                still_2fa = await self._check_for_2fa(page)
                if not still_2fa:
                    return True
                
                # Check for error messages
                error_found = await self._check_2fa_error(page)
                if error_found:
                    console.print(f"[red]✗[/] Invalid code (attempt {attempt + 1}/{max_attempts})")
                    
                    # Clear the input for retry
                    try:
                        await page.fill(input_selector, "")
                    except Exception:
                        pass
                else:
                    # Maybe it worked but page didn't change
                    return True
                    
            except Exception as e:
                console.print(f"[red]✗[/] Error entering 2FA code: {str(e)}")
        
        return False
    
    async def _find_2fa_submit(self, page: Page) -> Optional[str]:
        """Find the 2FA submit button."""
        selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Verify")',
            'button:has-text("Submit")',
            'button:has-text("Continue")',
            'button:has-text("Confirm")',
            '[class*="submit"]',
            '[class*="verify"]',
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
    
    async def _check_2fa_error(self, page: Page) -> bool:
        """Check if there's a 2FA error message."""
        error_selectors = [
            '[class*="error"]',
            '[class*="invalid"]',
            '[class*="incorrect"]',
            '[role="alert"]',
            '.alert-danger',
            '.alert-error',
        ]
        
        error_texts = [
            "invalid", "incorrect", "wrong", "expired",
            "try again", "not valid", "doesn't match",
        ]
        
        for selector in error_selectors:
            try:
                elems = await page.query_selector_all(selector)
                for elem in elems:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        text = await elem.text_content()
                        if text:
                            text_lower = text.lower()
                            for error_text in error_texts:
                                if error_text in text_lower:
                                    return True
            except Exception:
                pass
        
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
