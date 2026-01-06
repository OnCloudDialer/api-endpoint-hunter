"""Endpoint analyzer and schema detection."""

from __future__ import annotations

import copy
import json
import re
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse

from rich.console import Console

from .models import (
    CapturedEndpoint,
    EndpointGroup,
    HttpMethod,
    Parameter,
    ParameterLocation,
    RequestBody,
    ResponseBody,
    SchemaProperty,
    SchemaType,
    ContentType,
)

console = Console()

# Sensitive field names to redact
SENSITIVE_FIELDS = [
    "password", "passwd", "pwd", "pass",
    "secret", "token", "api_key", "apikey", "api-key",
    "auth", "authorization", "bearer",
    "credential", "private", "key",
    "session", "cookie", "jwt",
    "access_token", "refresh_token",
    "client_secret", "client_id",
]

# Patterns for non-API paths to filter out
NON_API_PATTERNS = [
    r"^/resources/",  # Resource/translation files
    r"\.(properties|json|xml|yaml|yml)$",  # Config files when not under /api/
    r"^/static/",
    r"^/assets/",
    r"^/_next/",
    r"^/__",
    r"\.(css|js|map|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot)(\?.*)?$",
]


class EndpointAnalyzer:
    """Analyzes captured endpoints and infers schemas."""
    
    def __init__(self, filter_non_api: bool = True, redact_sensitive: bool = True):
        self.endpoint_groups: dict[str, EndpointGroup] = {}
        self.filter_non_api = filter_non_api
        self.redact_sensitive = redact_sensitive
    
    def analyze(self, captured_endpoints: list[CapturedEndpoint]) -> list[EndpointGroup]:
        """Analyze captured endpoints and group by pattern."""
        
        console.print("\n[cyan]📊 Analyzing captured endpoints...[/]")
        
        # Filter out non-API endpoints
        if self.filter_non_api:
            original_count = len(captured_endpoints)
            captured_endpoints = [ep for ep in captured_endpoints if self._is_api_endpoint(ep)]
            filtered_count = original_count - len(captured_endpoints)
            if filtered_count > 0:
                console.print(f"  [dim]Filtered out {filtered_count} non-API endpoints[/]")
        
        # Group endpoints by their pattern
        groups: dict[str, list[CapturedEndpoint]] = defaultdict(list)
        
        for endpoint in captured_endpoints:
            endpoint_id = endpoint.endpoint_id
            groups[endpoint_id].append(endpoint)
        
        # Analyze each group
        analyzed_groups = []
        
        for endpoint_id, endpoints in groups.items():
            group = self._analyze_group(endpoints)
            if group:
                # Redact sensitive data
                if self.redact_sensitive:
                    group = self._redact_sensitive_data(group)
                analyzed_groups.append(group)
        
        # Sort by path
        analyzed_groups.sort(key=lambda g: (g.path_pattern, g.method.value))
        
        console.print(f"  [dim]Found {len(analyzed_groups)} unique endpoint patterns[/]")
        
        return analyzed_groups
    
    def _is_api_endpoint(self, endpoint: CapturedEndpoint) -> bool:
        """Check if endpoint is a real API (not resource file, static asset, etc.)."""
        path = endpoint.request.parsed_url["path"]
        
        # Always include /api/ paths
        if "/api/" in path.lower():
            return True
        
        # Check against non-API patterns
        for pattern in NON_API_PATTERNS:
            if re.search(pattern, path, re.I):
                return False
        
        # Check content type - JSON responses are likely APIs
        if endpoint.response.content_type == ContentType.JSON:
            return True
        
        # Exclude HTML responses (usually pages, not APIs)
        if endpoint.response.content_type == ContentType.HTML:
            return False
        
        return True
    
    def _redact_sensitive_data(self, group: EndpointGroup) -> EndpointGroup:
        """Redact sensitive data like passwords, tokens, etc."""
        # Deep copy to avoid modifying original
        group = group.model_copy(deep=True)
        
        # Redact request body
        if group.request_body:
            if group.request_body.example:
                group.request_body.example = self._redact_object(group.request_body.example)
            group.request_body.examples = [
                self._redact_object(ex) for ex in group.request_body.examples
            ]
            # Redact schema examples
            for prop_name, prop in group.request_body.schema_properties.items():
                self._redact_schema_property(prop_name, prop)
        
        # Redact response bodies
        for status_code, response in group.responses.items():
            if response.example:
                response.example = self._redact_object(response.example)
            response.examples = [
                self._redact_object(ex) for ex in response.examples
            ]
            # Redact schema examples
            for prop_name, prop in response.schema_properties.items():
                self._redact_schema_property(prop_name, prop)
        
        # Redact parameter examples
        for param in group.parameters:
            if self._is_sensitive_field(param.name):
                param.example = "***REDACTED***"
                param.examples = ["***REDACTED***"]
        
        return group
    
    def _redact_object(self, obj: Any) -> Any:
        """Recursively redact sensitive fields in an object."""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if self._is_sensitive_field(key):
                    result[key] = "***REDACTED***"
                else:
                    result[key] = self._redact_object(value)
            return result
        elif isinstance(obj, list):
            return [self._redact_object(item) for item in obj]
        return obj
    
    def _redact_schema_property(self, name: str, prop: SchemaProperty):
        """Redact sensitive schema property examples."""
        if self._is_sensitive_field(name):
            prop.example = "***REDACTED***"
        
        # Recurse into nested properties
        for nested_name, nested_prop in prop.properties.items():
            self._redact_schema_property(nested_name, nested_prop)
        
        # Handle array items
        if prop.items:
            self._redact_schema_property(name, prop.items)
    
    def _is_sensitive_field(self, name: str) -> bool:
        """Check if a field name is sensitive."""
        name_lower = name.lower()
        for sensitive in SENSITIVE_FIELDS:
            if sensitive in name_lower:
                return True
        return False
    
    def _analyze_group(self, endpoints: list[CapturedEndpoint]) -> Optional[EndpointGroup]:
        """Analyze a group of similar endpoints."""
        if not endpoints:
            return None
        
        first = endpoints[0]
        
        # Get base info from first endpoint
        parsed = urlparse(first.request.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path_pattern = first._normalize_path(parsed.path)
        
        group = EndpointGroup(
            method=first.request.method,
            path_pattern=path_pattern,
            base_url=base_url,
            captured=endpoints,
        )
        
        # Infer tags from path
        group.tags = self._infer_tags(path_pattern)
        
        # Generate summary
        group.summary = self._generate_summary(first.request.method, path_pattern)
        
        # Analyze parameters
        group.parameters = self._analyze_parameters(endpoints)
        
        # Analyze request body
        group.request_body = self._analyze_request_body(endpoints)
        
        # Analyze responses
        group.responses = self._analyze_responses(endpoints)
        
        return group
    
    def _infer_tags(self, path: str) -> list[str]:
        """Infer API tags from path."""
        # Remove common prefixes
        path = re.sub(r'^/?(api|v\d+)/', '', path)
        
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        
        if parts:
            # Use first meaningful path segment as tag
            tag = parts[0].replace("-", " ").replace("_", " ").title()
            return [tag]
        
        return ["General"]
    
    def _generate_summary(self, method: HttpMethod, path: str) -> str:
        """Generate a summary for the endpoint."""
        # Extract resource name from path
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        
        if not parts:
            resource = "resource"
        else:
            resource = parts[-1].replace("-", " ").replace("_", " ")
        
        # Check if it's a single item (has ID param)
        is_single = "{id}" in path
        
        method_actions = {
            HttpMethod.GET: "Get" if is_single else "List",
            HttpMethod.POST: "Create",
            HttpMethod.PUT: "Update",
            HttpMethod.PATCH: "Partially update",
            HttpMethod.DELETE: "Delete",
            HttpMethod.HEAD: "Check",
            HttpMethod.OPTIONS: "Get options for",
        }
        
        action = method_actions.get(method, method.value)
        
        if is_single:
            return f"{action} {resource}"
        return f"{action} {resource}"
    
    def _analyze_parameters(self, endpoints: list[CapturedEndpoint]) -> list[Parameter]:
        """Analyze and infer parameters from endpoints."""
        parameters = []
        
        # Analyze path parameters
        first = endpoints[0]
        path = first.request.parsed_url["path"]
        normalized = first._normalize_path(path)
        
        # Find {id} placeholders and infer original values
        original_parts = path.split("/")
        normalized_parts = normalized.split("/")
        
        for i, (orig, norm) in enumerate(zip(original_parts, normalized_parts)):
            if norm == "{id}" and orig != "{id}":
                param = Parameter(
                    name="id",
                    location=ParameterLocation.PATH,
                    required=True,
                    schema_type=self._infer_type(orig),
                    example=orig,
                    examples=list(set(
                        ep.request.parsed_url["path"].split("/")[i]
                        for ep in endpoints
                        if len(ep.request.parsed_url["path"].split("/")) > i
                    ))[:5],
                )
                # Check if already added
                if not any(p.name == "id" and p.location == ParameterLocation.PATH for p in parameters):
                    parameters.append(param)
        
        # Analyze query parameters
        query_params: dict[str, list[Any]] = defaultdict(list)
        
        for endpoint in endpoints:
            query = endpoint.request.parsed_url["query"]
            for name, values in query.items():
                query_params[name].extend(values)
        
        for name, values in query_params.items():
            unique_values = list(set(values))[:5]
            param = Parameter(
                name=name,
                location=ParameterLocation.QUERY,
                required=False,  # Assume optional for query params
                schema_type=self._infer_type(unique_values[0] if unique_values else ""),
                example=unique_values[0] if unique_values else None,
                examples=unique_values,
            )
            parameters.append(param)
        
        return parameters
    
    def _analyze_request_body(self, endpoints: list[CapturedEndpoint]) -> Optional[RequestBody]:
        """Analyze request bodies and infer schema."""
        # Only relevant for methods that typically have bodies
        first = endpoints[0]
        if first.request.method not in (HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH):
            return None
        
        # Collect all request bodies
        bodies = []
        for endpoint in endpoints:
            if endpoint.request.body:
                bodies.append((endpoint.request.content_type, endpoint.request.body))
        
        if not bodies:
            return None
        
        # Use first body as example
        content_type, body = bodies[0]
        
        request_body = RequestBody(
            content_type=content_type,
            example=self._parse_body(body, content_type),
            examples=[self._parse_body(b, ct) for ct, b in bodies[:3]],
        )
        
        # Infer schema from JSON bodies
        if content_type == ContentType.JSON:
            parsed = self._parse_body(body, content_type)
            if isinstance(parsed, dict):
                request_body.schema_properties = self._infer_object_schema(parsed)
        
        return request_body
    
    def _analyze_responses(self, endpoints: list[CapturedEndpoint]) -> dict[int, ResponseBody]:
        """Analyze responses and group by status code."""
        responses: dict[int, ResponseBody] = {}
        
        # Group by status code
        by_status: dict[int, list[CapturedEndpoint]] = defaultdict(list)
        for endpoint in endpoints:
            by_status[endpoint.response.status_code].append(endpoint)
        
        for status_code, status_endpoints in by_status.items():
            first = status_endpoints[0]
            
            response = ResponseBody(
                status_code=status_code,
                content_type=first.response.content_type,
                headers=dict(first.response.headers),
            )
            
            # Parse body
            if first.response.body:
                parsed = self._parse_body(first.response.body, first.response.content_type)
                response.example = parsed
                
                # Collect multiple examples
                response.examples = [
                    self._parse_body(ep.response.body, ep.response.content_type)
                    for ep in status_endpoints[:3]
                    if ep.response.body
                ]
                
                # Infer schema from JSON
                if first.response.content_type == ContentType.JSON and isinstance(parsed, dict):
                    response.schema_properties = self._infer_object_schema(parsed)
                elif first.response.content_type == ContentType.JSON and isinstance(parsed, list) and parsed:
                    if isinstance(parsed[0], dict):
                        response.schema_properties = self._infer_object_schema(parsed[0])
            
            responses[status_code] = response
        
        return responses
    
    def _parse_body(self, body: str, content_type: ContentType) -> Any:
        """Parse body content based on content type."""
        if content_type == ContentType.JSON:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return body
        return body
    
    def _infer_type(self, value: Any) -> SchemaType:
        """Infer schema type from a value."""
        if value is None:
            return SchemaType.NULL
        if isinstance(value, bool):
            return SchemaType.BOOLEAN
        if isinstance(value, int):
            return SchemaType.INTEGER
        if isinstance(value, float):
            return SchemaType.NUMBER
        if isinstance(value, list):
            return SchemaType.ARRAY
        if isinstance(value, dict):
            return SchemaType.OBJECT
        
        # String value - try to infer more specific type
        if isinstance(value, str):
            # Check for numeric string
            if value.isdigit():
                return SchemaType.INTEGER
            try:
                float(value)
                return SchemaType.NUMBER
            except ValueError:
                pass
            
            # Check for boolean string
            if value.lower() in ("true", "false"):
                return SchemaType.BOOLEAN
            
            # Check for UUID
            uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            if re.match(uuid_pattern, value, re.I):
                return SchemaType.STRING  # Still string, but could add format
        
        return SchemaType.STRING
    
    def _infer_format(self, name: str, value: Any) -> Optional[str]:
        """Infer the format of a value based on name and content."""
        name_lower = name.lower()
        
        # Check for timestamp by name
        if any(x in name_lower for x in ["date", "time", "timestamp", "created", "updated", "modified"]):
            if isinstance(value, int):
                # Unix timestamp in milliseconds (13 digits) or seconds (10 digits)
                if 1000000000000 <= value <= 9999999999999:
                    return "timestamp-ms"  # Unix timestamp in milliseconds
                elif 1000000000 <= value <= 9999999999:
                    return "timestamp"  # Unix timestamp in seconds
        
        # Check for email
        if "email" in name_lower:
            return "email"
        
        # Check for URL
        if any(x in name_lower for x in ["url", "link", "href", "uri"]):
            return "uri"
        
        # Check UUID by pattern
        if isinstance(value, str):
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
                return "uuid"
        
        return None
    
    def _infer_object_schema(self, obj: dict) -> dict[str, SchemaProperty]:
        """Infer schema properties from a JSON object."""
        properties = {}
        
        for key, value in obj.items():
            schema_type = self._infer_type(value)
            value_format = self._infer_format(key, value)
            
            # Generate description for special formats
            description = ""
            if value_format == "timestamp-ms":
                description = "Unix timestamp in milliseconds"
            elif value_format == "timestamp":
                description = "Unix timestamp in seconds"
            elif value_format == "uuid":
                description = "UUID identifier"
            
            prop = SchemaProperty(
                name=key,
                schema_type=schema_type,
                example=value if not isinstance(value, (dict, list)) else None,
                nullable=value is None,
                description=description,
            )
            
            # Handle nested objects
            if schema_type == SchemaType.OBJECT and isinstance(value, dict):
                prop.properties = self._infer_object_schema(value)
            
            # Handle arrays
            if schema_type == SchemaType.ARRAY and isinstance(value, list) and value:
                first_item = value[0]
                item_type = self._infer_type(first_item)
                prop.items = SchemaProperty(
                    name="items",
                    schema_type=item_type,
                    example=first_item if not isinstance(first_item, (dict, list)) else None,
                )
                if item_type == SchemaType.OBJECT and isinstance(first_item, dict):
                    prop.items.properties = self._infer_object_schema(first_item)
            
            properties[key] = prop
        
        return properties
