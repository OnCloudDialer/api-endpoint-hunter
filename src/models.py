"""Data models for API Endpoint Hunter."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from pydantic import BaseModel, Field, computed_field


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ContentType(str, Enum):
    JSON = "application/json"
    FORM = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    XML = "application/xml"
    TEXT = "text/plain"
    HTML = "text/html"
    UNKNOWN = "unknown"


class ParameterLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"


class SchemaType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    NULL = "null"


class Parameter(BaseModel):
    """Represents an API parameter."""
    
    name: str
    location: ParameterLocation
    required: bool = False
    schema_type: SchemaType = SchemaType.STRING
    description: str = ""
    example: Any = None
    examples: list[Any] = Field(default_factory=list)


class SchemaProperty(BaseModel):
    """Represents a property in a JSON schema."""
    
    name: str
    schema_type: SchemaType
    description: str = ""
    example: Any = None
    nullable: bool = False
    items: Optional[SchemaProperty] = None  # For arrays
    properties: dict[str, SchemaProperty] = Field(default_factory=dict)  # For objects


class RequestBody(BaseModel):
    """Represents a request body."""
    
    content_type: ContentType
    schema_properties: dict[str, SchemaProperty] = Field(default_factory=dict)
    example: Any = None
    examples: list[Any] = Field(default_factory=list)


class ResponseBody(BaseModel):
    """Represents a response body."""
    
    status_code: int
    content_type: ContentType
    schema_properties: dict[str, SchemaProperty] = Field(default_factory=dict)
    example: Any = None
    examples: list[Any] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)


class CapturedRequest(BaseModel):
    """A captured HTTP request from the browser."""
    
    url: str
    method: HttpMethod
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    @computed_field
    @property
    def parsed_url(self) -> dict:
        parsed = urlparse(self.url)
        return {
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "query": parse_qs(parsed.query),
        }
    
    @computed_field
    @property
    def content_type(self) -> ContentType:
        ct = self.headers.get("content-type", "").lower()
        if "json" in ct:
            return ContentType.JSON
        elif "form-urlencoded" in ct:
            return ContentType.FORM
        elif "multipart" in ct:
            return ContentType.MULTIPART
        elif "xml" in ct:
            return ContentType.XML
        return ContentType.UNKNOWN


class CapturedResponse(BaseModel):
    """A captured HTTP response from the browser."""
    
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    @computed_field
    @property
    def content_type(self) -> ContentType:
        ct = self.headers.get("content-type", "").lower()
        if "json" in ct:
            return ContentType.JSON
        elif "xml" in ct:
            return ContentType.XML
        elif "html" in ct:
            return ContentType.HTML
        elif "text" in ct:
            return ContentType.TEXT
        return ContentType.UNKNOWN


class CapturedEndpoint(BaseModel):
    """A captured API endpoint with request and response."""
    
    request: CapturedRequest
    response: CapturedResponse
    source_page: str = ""  # URL of the page that made this request
    
    @computed_field
    @property
    def endpoint_id(self) -> str:
        """Unique identifier for this endpoint pattern."""
        # Normalize path by replacing likely IDs with placeholders
        path = self.request.parsed_url["path"]
        normalized = self._normalize_path(path)
        key = f"{self.request.method}:{normalized}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    @staticmethod
    def _normalize_path(path: str) -> str:
        """Replace IDs and UUIDs in path with placeholders."""
        import re
        parts = path.split("/")
        normalized = []
        for part in parts:
            # UUID pattern
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
                normalized.append("{id}")
            # Numeric ID
            elif re.match(r'^\d+$', part):
                normalized.append("{id}")
            # MongoDB ObjectId
            elif re.match(r'^[0-9a-f]{24}$', part, re.I):
                normalized.append("{id}")
            else:
                normalized.append(part)
        return "/".join(normalized)


class EndpointGroup(BaseModel):
    """A group of captured endpoints with the same pattern."""
    
    method: HttpMethod
    path_pattern: str
    base_url: str
    captured: list[CapturedEndpoint] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: Optional[RequestBody] = None
    responses: dict[int, ResponseBody] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    summary: str = ""
    description: str = ""
    
    @computed_field
    @property
    def operation_id(self) -> str:
        """Generate an operation ID for this endpoint."""
        method = self.method.value.lower()
        # Convert path to camelCase operation name
        parts = [p for p in self.path_pattern.split("/") if p and not p.startswith("{")]
        if parts:
            name = parts[-1]
            if len(parts) > 1:
                name = "".join(p.title() for p in parts)
            return f"{method}{name.title()}"
        return f"{method}Root"


class CrawlConfig(BaseModel):
    """Configuration for the crawl session."""
    
    start_url: str
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    auth_headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    max_pages: int = 50
    max_depth: int = 3
    wait_time: int = 2000
    headless: bool = True
    output_dir: str = "./api-docs"
    output_format: str = "both"  # openapi, markdown, both
    
    # Filtering
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=lambda: [
        r".*\.(png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|eot)(\?.*)?$",
        r".*/sockjs-node/.*",
        r".*/hot-update\.json$",
    ])


class CrawlResult(BaseModel):
    """Result of a crawl session."""
    
    config: CrawlConfig
    endpoints: list[EndpointGroup] = Field(default_factory=list)
    pages_visited: list[str] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    errors: list[str] = Field(default_factory=list)
    
    @computed_field
    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @computed_field
    @property
    def total_endpoints(self) -> int:
        return len(self.endpoints)
    
    @computed_field
    @property
    def total_requests_captured(self) -> int:
        return sum(len(ep.captured) for ep in self.endpoints)
