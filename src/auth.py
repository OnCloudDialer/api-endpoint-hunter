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
                await asyncio.sleep(3)
                try:
                    await page.wait_for_load_state("networkidle", timeout=15000)
                except Exception:
                    pass
            
            # IMPORTANT: Navigate to start URL to verify login worked
            console.print("[cyan]  Verifying authentication by navigating to target...[/]")
            await page.goto(self.config.start_url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(2)
            
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            
            # Check if we were redirected back to login (auth failed)
            current_url = page.url.lower()
            if "login" in current_url or "signin" in current_url or "auth" in current_url:
                console.print("[red]✗[/] Authentication failed - redirected back to login page")
                console.print(f"  [dim]Current URL: {page.url}[/]")
                return False
            
            # Check for logged-in indicators
            logged_in_selectors = [
                "[class*='logout']", "[class*='signout']",
                "[href*='logout']", "[href*='signout']",
                ".user-menu", ".profile-menu", ".account-menu",
                "[class*='user-name']", "[class*='username']",
                "[class*='avatar']", "[class*='profile']",
            ]
            
            for selector in logged_in_selectors:
                try:
                    elem = await page.query_selector(selector)
                    if elem:
                        console.print("[green]✓[/] Login successful (found logged-in indicator)")
                        return True
                except Exception:
                    pass
            
            # If we're on the start URL and not redirected to login, probably successful
            if self.config.start_url.rstrip('/') in page.url:
                console.print("[green]✓[/] Login successful (on target page)")
                return True
            
            console.print("[yellow]?[/] Login status unclear, continuing anyway")
            console.print(f"  [dim]Current URL: {page.url}[/]")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/] Login failed: {str(e)}")
            return False
    
    async def _check_for_2fa(self, page: Page) -> bool:
        """Check if the page is showing a 2FA/MFA prompt."""
        
        # Take a screenshot to help debug 2FA detection
        try:
            import os
            from datetime import datetime
            screenshot_dir = os.path.join(os.getcwd(), "api-docs", "snapshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%H%M%S")
            screenshot_path = os.path.join(screenshot_dir, f"2fa_check_{timestamp}.png")
            await page.screenshot(path=screenshot_path)
            console.print(f"  [dim]📸 2FA check screenshot: {screenshot_path}[/]")
        except Exception as e:
            console.print(f"  [dim]Could not save 2FA screenshot: {e}[/]")
        
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
    
    async def _find_2fa_input(self, page: Page):
        """Find the 2FA code input field. Returns (selector_or_element, is_element_handle)."""
        from playwright.async_api import ElementHandle
        
        # Definitely skip these - username/password fields
        skip_exact = ["user-id", "userid", "username", "email", "login", "password", "pass", "pwd"]
        skip_placeholders = ["email", "username", "user name", "user id", "login", "password"]
        
        # FIRST: Look for modal dialogs - 2FA is often in a popup modal
        modal_selectors = [
            '[role="dialog"] input[type="text"]',
            '[role="dialog"] input:not([type])',
            '.modal input[type="text"]',
            '.modal input:not([type])',
            '[class*="modal"] input[type="text"]',
            '[class*="modal"] input:not([type])',
            '[class*="dialog"] input[type="text"]',
            '[class*="dialog"] input:not([type])',
            '[class*="popup"] input[type="text"]',
            '[class*="verify"] input[type="text"]',
            '[class*="verify"] input:not([type])',
            '[class*="2fa"] input',
            '[class*="mfa"] input',
            '[class*="otp"] input',
        ]
        
        for selector in modal_selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        elem_type = await elem.get_attribute("type") or ""
                        if elem_type != "password":
                            console.print(f"  [dim]Found 2FA field in modal: {selector}[/]")
                            return (selector, False)
            except Exception:
                pass
        
        # Second: Look for inputs near 2FA-related text
        try:
            # Find elements containing verification text
            verify_texts = await page.query_selector_all('//*[contains(text(), "Verify") or contains(text(), "verification") or contains(text(), "authentication code")]')
            for text_elem in verify_texts:
                # Look for nearby input
                parent = await text_elem.evaluate_handle('el => el.closest("div, form, section")')
                if parent:
                    inp = await parent.query_selector('input[type="text"], input:not([type="password"]):not([type="hidden"]):not([type="checkbox"])')
                    if inp:
                        is_visible = await inp.is_visible()
                        if is_visible:
                            console.print(f"  [dim]Found 2FA field near verification text[/]")
                            return (inp, True)
        except Exception as e:
            console.print(f"  [dim]Error searching near text: {e}[/]")
        
        # Third: Look for very specific 2FA selectors (high confidence)
        high_confidence_selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name*="otp"]',
            'input[name*="totp"]',
            'input[name*="2fa"]',
            'input[name*="mfa"]',
            'input[name*="verification"]',
            'input[name*="authenticator"]',
        ]
        
        for selector in high_confidence_selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        console.print(f"  [dim]Found 2FA field (high confidence): {selector}[/]")
                        return (selector, False)
            except Exception:
                pass
        
        # Second pass: Look for numeric inputs that could be 2FA
        numeric_selectors = [
            'input[inputmode="numeric"]',
            'input[maxlength="6"]',
            'input[maxlength="4"]',
            'input[type="tel"]',
            'input[type="number"]',
            'input[name*="code"]',
            'input[name*="token"]',
            'input[name*="pin"]',
        ]
        
        for selector in numeric_selectors:
            try:
                elems = await page.query_selector_all(selector)
                for elem in elems:
                    is_visible = await elem.is_visible()
                    if not is_visible:
                        continue
                    
                    elem_id = await elem.get_attribute("id") or ""
                    elem_name = await elem.get_attribute("name") or ""
                    elem_type = await elem.get_attribute("type") or ""
                    
                    # Skip password fields
                    if elem_type == "password":
                        continue
                    
                    # Skip exact matches for username fields
                    id_lower = elem_id.lower()
                    name_lower = elem_name.lower()
                    if id_lower in skip_exact or name_lower in skip_exact:
                        console.print(f"  [dim]Skipping field (looks like username): {elem_id or elem_name}[/]")
                        continue
                    
                    console.print(f"  [dim]Found 2FA field (numeric): {selector}[/]")
                    return (selector, False)
            except Exception:
                pass
        
        # Third pass: Any visible text input that's not obviously username/password
        console.print("  [dim]Searching for any suitable input field...[/]")
        try:
            # First, list ALL visible input fields for debugging
            all_inputs = await page.query_selector_all('input')
            console.print(f"  [dim]Found {len(all_inputs)} total input fields on page[/]")
            
            visible_text_inputs = []
            for i, inp in enumerate(all_inputs):
                is_visible = await inp.is_visible()
                elem_id = await inp.get_attribute("id") or ""
                elem_name = await inp.get_attribute("name") or ""
                elem_type = await inp.get_attribute("type") or ""
                elem_placeholder = await inp.get_attribute("placeholder") or ""
                elem_class = await inp.get_attribute("class") or ""
                
                if is_visible:
                    console.print(f"  [dim]  Input {i}: type={elem_type}, id={elem_id}, name={elem_name}, placeholder={elem_placeholder[:30] if elem_placeholder else ''}, class={elem_class[:30] if elem_class else ''}[/]")
                    
                    # Skip password fields
                    if elem_type == "password":
                        continue
                    
                    # Skip hidden inputs
                    if elem_type == "hidden":
                        continue
                    
                    # Skip checkbox/radio
                    if elem_type in ["checkbox", "radio", "submit", "button"]:
                        continue
                    
                    visible_text_inputs.append((inp, elem_id, elem_name, elem_placeholder, elem_class))
            
            console.print(f"  [dim]Found {len(visible_text_inputs)} visible text-like inputs[/]")
            
            # Now find the best candidate - prefer fields NOT associated with username/email
            for inp, elem_id, elem_name, elem_placeholder, elem_class in visible_text_inputs:
                id_lower = elem_id.lower()
                name_lower = elem_name.lower()
                placeholder_lower = elem_placeholder.lower()
                class_lower = elem_class.lower()
                
                # Skip if looks like username field
                if id_lower in skip_exact or name_lower in skip_exact:
                    continue
                
                # Skip if placeholder indicates username/email
                if any(x in placeholder_lower for x in skip_placeholders):
                    continue
                
                # Skip if class indicates username/email
                if any(x in class_lower for x in ["user", "email", "login", "account"]):
                    continue
                
                console.print(f"  [dim]Selected 2FA field: id={elem_id}, name={elem_name}[/]")
                
                if elem_id:
                    return (f'#{elem_id}', False)
                elif elem_name:
                    return (f'input[name="{elem_name}"]', False)
                
                # No id/name - return element handle
                console.print(f"  [dim]Using element handle (no id/name available)[/]")
                return (inp, True)
            
            # If we got here, all visible inputs look like username fields
            # As last resort, if there's only ONE visible text input after filtering password, use it
            if len(visible_text_inputs) == 1:
                inp, elem_id, elem_name, elem_placeholder, elem_class = visible_text_inputs[0]
                console.print(f"  [dim]Only one visible input, using it: id={elem_id}, name={elem_name}[/]")
                if elem_id:
                    return (f'#{elem_id}', False)
                elif elem_name:
                    return (f'input[name="{elem_name}"]', False)
                return (inp, True)
                
        except Exception as e:
            console.print(f"  [dim]Error searching inputs: {e}[/]")
        
        return (None, False)
    
    async def _handle_2fa(self, page: Page, max_attempts: int = 3) -> bool:
        """Handle 2FA code entry."""
        global _2fa_callback
        
        result = await self._find_2fa_input(page)
        input_target, is_element = result
        
        if not input_target:
            console.print("[red]✗[/] Could not find 2FA input field")
            return False
        
        if is_element:
            console.print(f"  [dim]2FA input field: (element handle)[/]")
        else:
            console.print(f"  [dim]2FA input field: {input_target}[/]")
        
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
                if is_element:
                    # Use element handle directly
                    await input_target.fill(code)
                    await asyncio.sleep(0.5)
                    
                    # Try to submit
                    submit_selector = await self._find_2fa_submit(page)
                    if submit_selector:
                        await page.click(submit_selector)
                    else:
                        await input_target.press("Enter")
                else:
                    # Use selector
                    await page.fill(input_target, code)
                    await asyncio.sleep(0.5)
                    
                    # Try to submit
                    submit_selector = await self._find_2fa_submit(page)
                    if submit_selector:
                        await page.click(submit_selector)
                    else:
                        await page.press(input_target, "Enter")
                
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
                        if is_element:
                            await input_target.fill("")
                        else:
                            await page.fill(input_target, "")
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
        # Prioritize buttons in modals/dialogs with verification text
        modal_button_selectors = [
            '[role="dialog"] button:has-text("Verify")',
            '[class*="modal"] button:has-text("Verify")',
            '[class*="dialog"] button:has-text("Verify")',
            'button:has-text("Verify")',
            '[role="dialog"] button[type="submit"]',
            '[class*="modal"] button[type="submit"]',
        ]
        
        for selector in modal_button_selectors:
            try:
                elem = await page.query_selector(selector)
                if elem:
                    is_visible = await elem.is_visible()
                    if is_visible:
                        text = await elem.text_content()
                        console.print(f"  [dim]Found 2FA submit button: {text}[/]")
                        return selector
            except Exception:
                pass
        
        # Fallback to generic selectors
        selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
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
