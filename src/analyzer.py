"""Endpoint analyzer and schema detection."""

from __future__ import annotations

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


class EndpointAnalyzer:
    """Analyzes captured endpoints and infers schemas."""
    
    def __init__(self):
        self.endpoint_groups: dict[str, EndpointGroup] = {}
    
    def analyze(self, captured_endpoints: list[CapturedEndpoint]) -> list[EndpointGroup]:
        """Analyze captured endpoints and group by pattern."""
        
        console.print("\n[cyan]📊 Analyzing captured endpoints...[/]")
        
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
                analyzed_groups.append(group)
        
        # Sort by path
        analyzed_groups.sort(key=lambda g: (g.path_pattern, g.method.value))
        
        console.print(f"  [dim]Found {len(analyzed_groups)} unique endpoint patterns[/]")
        
        return analyzed_groups
    
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
    
    def _infer_object_schema(self, obj: dict) -> dict[str, SchemaProperty]:
        """Infer schema properties from a JSON object."""
        properties = {}
        
        for key, value in obj.items():
            schema_type = self._infer_type(value)
            
            prop = SchemaProperty(
                name=key,
                schema_type=schema_type,
                example=value if not isinstance(value, (dict, list)) else None,
                nullable=value is None,
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
