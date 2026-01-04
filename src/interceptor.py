"""Network interceptor for capturing API requests and responses."""

from __future__ import annotations

import re
import json
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse

from playwright.async_api import Page, Request, Response, Route
from rich.console import Console

from .models import (
    CapturedEndpoint,
    CapturedRequest,
    CapturedResponse,
    CrawlConfig,
    HttpMethod,
)

console = Console()


class APIInterceptor:
    """Intercepts and captures API calls from browser network traffic."""
    
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.captured_endpoints: list[CapturedEndpoint] = []
        self._pending_requests: dict[str, tuple[CapturedRequest, str]] = {}
        self._exclude_patterns = [re.compile(p) for p in config.exclude_patterns]
        self._include_patterns = [re.compile(p) for p in config.include_patterns] if config.include_patterns else None
        
    def _should_capture(self, url: str, resource_type: str) -> bool:
        """Determine if this request should be captured as an API call."""
        # Skip non-API resource types
        if resource_type in ("document", "stylesheet", "image", "font", "media", "manifest"):
            return False
        
        # Check exclusion patterns
        for pattern in self._exclude_patterns:
            if pattern.match(url):
                return False
        
        # If include patterns specified, URL must match at least one
        if self._include_patterns:
            return any(pattern.match(url) for pattern in self._include_patterns)
        
        # Heuristics for API detection
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Common API path indicators
        api_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/", "/graphql",
            "/rest/", "/data/", "/ajax/", "/json/",
        ]
        
        if any(indicator in path for indicator in api_indicators):
            return True
        
        # XHR/Fetch requests to same origin with JSON are likely API calls
        if resource_type in ("xhr", "fetch"):
            return True
        
        return False
    
    async def setup(self, page: Page, current_page_url: Callable[[], str]):
        """Set up request/response interception on the page."""
        
        async def handle_request(request: Request):
            """Capture outgoing requests."""
            url = request.url
            resource_type = request.resource_type
            
            if not self._should_capture(url, resource_type):
                return
            
            try:
                method = HttpMethod(request.method.upper())
            except ValueError:
                return  # Skip unknown methods
            
            # Get request body if present
            body = None
            try:
                post_data = request.post_data
                if post_data:
                    body = post_data
            except Exception:
                pass
            
            # Capture headers (filter out sensitive ones for logging)
            headers = dict(request.headers)
            
            captured_request = CapturedRequest(
                url=url,
                method=method,
                headers=headers,
                body=body,
                timestamp=datetime.now(),
            )
            
            # Store pending request with source page
            request_id = f"{request.method}:{url}:{id(request)}"
            self._pending_requests[request_id] = (captured_request, current_page_url())
            
            console.print(f"  [dim cyan]→ {method.value}[/] [dim]{self._truncate_url(url)}[/]")
        
        async def handle_response(response: Response):
            """Capture incoming responses and match with requests."""
            request = response.request
            url = request.url
            resource_type = request.resource_type
            
            if not self._should_capture(url, resource_type):
                return
            
            request_id = f"{request.method}:{url}:{id(request)}"
            
            if request_id not in self._pending_requests:
                return
            
            captured_request, source_page = self._pending_requests.pop(request_id)
            
            # Get response body
            body = None
            try:
                body = await response.text()
            except Exception:
                try:
                    body_bytes = await response.body()
                    body = body_bytes.decode("utf-8", errors="replace")
                except Exception:
                    pass
            
            # Capture response headers
            headers = dict(response.headers)
            
            captured_response = CapturedResponse(
                status_code=response.status,
                headers=headers,
                body=body,
                timestamp=datetime.now(),
            )
            
            endpoint = CapturedEndpoint(
                request=captured_request,
                response=captured_response,
                source_page=source_page,
            )
            
            self.captured_endpoints.append(endpoint)
            
            status_color = "green" if 200 <= response.status < 300 else "yellow" if response.status < 400 else "red"
            console.print(f"  [dim {status_color}]← {response.status}[/] [dim]{self._truncate_url(url)}[/]")
        
        # Attach listeners
        page.on("request", handle_request)
        page.on("response", handle_response)
    
    def _truncate_url(self, url: str, max_len: int = 80) -> str:
        """Truncate URL for display."""
        if len(url) <= max_len:
            return url
        return url[:max_len - 3] + "..."
    
    def get_captured_endpoints(self) -> list[CapturedEndpoint]:
        """Get all captured endpoints."""
        return self.captured_endpoints.copy()
    
    def clear(self):
        """Clear captured endpoints."""
        self.captured_endpoints.clear()
        self._pending_requests.clear()
