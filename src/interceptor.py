"""Network interceptor for capturing API requests and responses."""

from __future__ import annotations

import re
import json
import hashlib
from datetime import datetime
from typing import Callable, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote

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
        
        # For deduplication - track unique API patterns
        self._seen_api_patterns: set[str] = set()
        self._duplicate_count: int = 0
    
    def _extract_path_params(self, path: str) -> dict[str, str]:
        """Extract potential path parameters (IDs, UUIDs, etc.)"""
        params = {}
        parts = path.split('/')
        
        for i, part in enumerate(parts):
            if not part:
                continue
            
            # Detect numeric IDs
            if part.isdigit():
                params[f"path_param_{i}"] = {"value": part, "type": "integer", "description": "Numeric ID"}
            # Detect UUIDs
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
                params[f"path_param_{i}"] = {"value": part, "type": "uuid", "description": "UUID identifier"}
            # Detect hex IDs (like MongoDB ObjectIds)
            elif re.match(r'^[0-9a-f]{24}$', part, re.I):
                params[f"path_param_{i}"] = {"value": part, "type": "objectid", "description": "Object ID"}
            # Detect slugs (words with dashes)
            elif re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)+$', part, re.I):
                params[f"path_param_{i}"] = {"value": part, "type": "slug", "description": "URL slug"}
        
        return params
    
    def _extract_query_params(self, url: str) -> dict[str, Any]:
        """Extract and analyze query parameters."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        analyzed_params = {}
        for key, values in query_params.items():
            value = values[0] if len(values) == 1 else values
            
            # Infer type
            param_info = {"value": value}
            if isinstance(value, str):
                if value.isdigit():
                    param_info["type"] = "integer"
                elif value.lower() in ('true', 'false'):
                    param_info["type"] = "boolean"
                elif re.match(r'^\d{4}-\d{2}-\d{2}', value):
                    param_info["type"] = "date"
                else:
                    param_info["type"] = "string"
            else:
                param_info["type"] = "array"
            
            analyzed_params[key] = param_info
        
        return analyzed_params
    
    def _extract_body_params(self, body: str, content_type: str = "") -> dict[str, Any]:
        """Extract and analyze request body parameters."""
        if not body:
            return {}
        
        # Try JSON
        if "json" in content_type.lower() or body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body)
                return self._analyze_json_structure(data)
            except json.JSONDecodeError:
                pass
        
        # Try form data
        if "form" in content_type.lower() or "=" in body:
            try:
                params = parse_qs(body)
                return {k: {"value": v[0] if len(v) == 1 else v, "type": "string"} for k, v in params.items()}
            except:
                pass
        
        return {"raw_body": {"value": body[:500], "type": "raw"}}
    
    def _analyze_json_structure(self, data: Any, prefix: str = "") -> dict[str, Any]:
        """Recursively analyze JSON structure to extract parameter info."""
        result = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, dict):
                    result.update(self._analyze_json_structure(value, full_key))
                elif isinstance(value, list):
                    result[full_key] = {
                        "type": "array",
                        "value": value[:3] if len(value) > 3 else value,  # Sample
                        "item_type": type(value[0]).__name__ if value else "unknown"
                    }
                else:
                    result[full_key] = {
                        "type": type(value).__name__,
                        "value": value
                    }
        elif isinstance(data, list):
            result["items"] = {
                "type": "array",
                "value": data[:3] if len(data) > 3 else data,
                "item_type": type(data[0]).__name__ if data else "unknown"
            }
        
        return result
    
    def _get_api_signature(self, method: str, url: str, body: str = "") -> str:
        """Generate a signature to identify duplicate API patterns."""
        parsed = urlparse(url)
        
        # Normalize path - replace IDs with placeholders
        path = parsed.path
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)  # numeric IDs
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)', '/{uuid}', path, flags=re.I)
        path = re.sub(r'/[0-9a-f]{24}(?=/|$)', '/{objectid}', path, flags=re.I)
        
        # Include query param keys (not values) in signature
        query_keys = sorted(parse_qs(parsed.query).keys())
        
        signature = f"{method}:{parsed.netloc}{path}:{','.join(query_keys)}"
        return signature
    
    def _is_duplicate_api(self, method: str, url: str, body: str = "") -> bool:
        """Check if we've already captured this API pattern."""
        signature = self._get_api_signature(method, url, body)
        
        if signature in self._seen_api_patterns:
            self._duplicate_count += 1
            return True
        
        self._seen_api_patterns.add(signature)
        return False
        
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
            
            # Check for duplicate API pattern
            if self._is_duplicate_api(method.value, url, body or ""):
                console.print(f"  [dim yellow]↺ Duplicate API pattern, skipping[/]")
                return
            
            # Capture headers (filter out sensitive ones for logging)
            headers = dict(request.headers)
            
            # Extract parameters
            content_type = headers.get("content-type", "")
            parsed_url = urlparse(url)
            
            path_params = self._extract_path_params(parsed_url.path)
            query_params = self._extract_query_params(url)
            body_params = self._extract_body_params(body, content_type) if body else {}
            
            captured_request = CapturedRequest(
                url=url,
                method=method,
                headers=headers,
                body=body,
                timestamp=datetime.now(),
                path_params=path_params,
                query_params=query_params,
                body_params=body_params,
            )
            
            # Store pending request with source page
            request_id = f"{request.method}:{url}:{id(request)}"
            self._pending_requests[request_id] = (captured_request, current_page_url())
            
            console.print(f"  [dim cyan]→ {method.value}[/] [dim]{self._truncate_url(url)}[/]")
            if query_params:
                console.print(f"    [dim]Query: {list(query_params.keys())}[/]")
            if body_params:
                console.print(f"    [dim]Body: {list(body_params.keys())[:5]}...[/]")
        
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
