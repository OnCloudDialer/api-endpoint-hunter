"""Web interface for API Endpoint Hunter."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import CrawlConfig, CapturedEndpoint, CapturedRequest, CapturedResponse, HttpMethod, ContentType
from src.crawler import Crawler
from src.analyzer import EndpointAnalyzer
from src.generator import DocumentationWriter, MarkdownGenerator, OpenAPIGenerator
from src.auth import set_2fa_callback, AuthHandler
from src.config_manager import save_profile, load_profile, list_profiles, delete_profile

app = FastAPI(title="API Endpoint Hunter")

# Store active crawl state
crawl_state = {
    "running": False,
    "progress": [],
    "result": None,
    "endpoints": [],
    "waiting_for_2fa": False,
    "2fa_code": None,
    "2fa_event": None,
    "crawl_task": None,  # Track the background task
    "snapshots": [],  # List of snapshot info
}

# Store record mode state
record_state = {
    "recording": False,
    "browser": None,
    "context": None,
    "page": None,
    "captured_endpoints": [],  # Raw captured
    "endpoint_groups": {},  # Grouped by pattern with user edits
    "task": None,
}

# Serve snapshots directory
snapshots_dir = Path(__file__).parent.parent / "api-docs" / "snapshots"
snapshots_dir.mkdir(parents=True, exist_ok=True)


class CrawlRequest(BaseModel):
    url: str
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    auth_headers: dict = {}
    cookies: dict = {}
    max_pages: int = 50
    max_depth: int = 3
    wait_time: int = 2000
    headless: bool = True


class SaveProfileRequest(BaseModel):
    name: str
    description: str = ""
    config: CrawlRequest


class RecordRequest(BaseModel):
    url: str
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None


class EndpointEditRequest(BaseModel):
    endpoint_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    skip: bool = False


# WebSocket connections for live updates
connected_clients: list[WebSocket] = []


async def broadcast(message: dict):
    """Send message to all connected clients."""
    print(f"Broadcasting to {len(connected_clients)} clients: {message.get('type', 'unknown')}")
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception as e:
            print(f"Failed to send to client: {e}")
            disconnected.append(client)
    
    # Remove disconnected clients
    for client in disconnected:
        if client in connected_clients:
            connected_clients.remove(client)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    print(f"WebSocket connected. Total clients: {len(connected_clients)}")
    try:
        while True:
            # Keep connection alive - use ping/pong or just wait for messages
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a ping to keep the connection alive
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
        print(f"WebSocket disconnected. Total clients: {len(connected_clients)}")


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main interface."""
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(content=html_path.read_text())


@app.get("/api/status")
async def get_status():
    """Get current crawl status."""
    return {
        "running": crawl_state["running"],
        "progress_count": len(crawl_state["progress"]),
        "endpoints_count": len(crawl_state["endpoints"]),
    }


@app.get("/api/endpoints")
async def get_endpoints():
    """Get discovered endpoints."""
    return crawl_state["endpoints"]


@app.get("/api/docs/openapi")
async def get_openapi_doc():
    """Get the generated OpenAPI spec."""
    docs_path = Path(__file__).parent.parent / "api-docs" / "openapi.yaml"
    if docs_path.exists():
        return FileResponse(docs_path, media_type="text/yaml")
    return JSONResponse({"error": "No documentation generated yet"}, status_code=404)


@app.get("/api/docs/markdown")
async def get_markdown_doc():
    """Get the generated Markdown doc."""
    docs_path = Path(__file__).parent.parent / "api-docs" / "api-docs.md"
    if docs_path.exists():
        return FileResponse(docs_path, media_type="text/markdown")
    return JSONResponse({"error": "No documentation generated yet"}, status_code=404)


# Snapshot endpoints
@app.get("/api/snapshots")
async def get_snapshots():
    """Get list of all snapshots from current/last crawl."""
    index_path = snapshots_dir / "index.json"
    if index_path.exists():
        with open(index_path) as f:
            snapshots = json.load(f)
        return {"snapshots": snapshots}
    return {"snapshots": crawl_state.get("snapshots", [])}


@app.get("/api/snapshots/{filename}")
async def get_snapshot(filename: str):
    """Get a specific snapshot image."""
    # Sanitize filename to prevent directory traversal
    safe_filename = Path(filename).name
    filepath = snapshots_dir / safe_filename
    if filepath.exists() and filepath.suffix.lower() in ('.png', '.jpg', '.jpeg'):
        return FileResponse(filepath, media_type="image/png")
    return JSONResponse({"error": "Snapshot not found"}, status_code=404)


# Profile management endpoints
@app.get("/api/profiles")
async def get_profiles():
    """List all saved profiles."""
    profiles = list_profiles()
    return {"profiles": profiles}


@app.get("/api/profiles/{name}")
async def get_profile(name: str):
    """Load a specific profile."""
    config = load_profile(name)
    if not config:
        return JSONResponse({"error": "Profile not found"}, status_code=404)
    
    return {
        "name": name,
        "config": {
            "url": config.start_url,
            "login_url": config.login_url,
            "username": config.username,
            "password": config.password,
            "username_field": config.username_field,
            "password_field": config.password_field,
            "auth_headers": config.auth_headers,
            "cookies": config.cookies,
            "max_pages": config.max_pages,
            "max_depth": config.max_depth,
            "wait_time": config.wait_time,
            "headless": config.headless,
        }
    }


@app.post("/api/profiles")
async def create_profile(request: SaveProfileRequest):
    """Save a new profile."""
    try:
        # Validate
        if not request.name or not request.name.strip():
            return JSONResponse({"error": "Profile name is required"}, status_code=400)
        
        if not request.config.url:
            return JSONResponse({"error": "URL is required"}, status_code=400)
        
        config = CrawlConfig(
            start_url=request.config.url,
            login_url=request.config.login_url,
            username=request.config.username,
            password=request.config.password,
            username_field=request.config.username_field,
            password_field=request.config.password_field,
            auth_headers=request.config.auth_headers or {},
            cookies=request.config.cookies or {},
            max_pages=request.config.max_pages or 50,
            max_depth=request.config.max_depth or 3,
            wait_time=request.config.wait_time or 2000,
            headless=request.config.headless if request.config.headless is not None else True,
        )
        
        save_profile(request.name.strip(), config, request.description or "")
        return {"status": "saved", "name": request.name.strip()}
    except Exception as e:
        return JSONResponse({"error": f"Failed to save profile: {str(e)}"}, status_code=500)


@app.delete("/api/profiles/{name}")
async def remove_profile(name: str):
    """Delete a profile."""
    success = delete_profile(name)
    if success:
        return {"status": "deleted"}
    return JSONResponse({"error": "Profile not found"}, status_code=404)


@app.post("/api/crawl")
async def start_crawl(request: CrawlRequest):
    """Start a new crawl."""
    # Check if a crawl is truly running (task exists and isn't done)
    task = crawl_state.get("crawl_task")
    if task and not task.done():
        return JSONResponse({"error": "A crawl is already in progress"}, status_code=400)
    
    # Validate URL
    if not request.url or not request.url.startswith(('http://', 'https://')):
        return JSONResponse({"error": "Invalid URL. Must start with http:// or https://"}, status_code=400)
    
    # Reset ALL state
    crawl_state["running"] = True
    crawl_state["progress"] = []
    crawl_state["result"] = None
    crawl_state["endpoints"] = []
    crawl_state["waiting_for_2fa"] = False
    crawl_state["2fa_code"] = None
    crawl_state["2fa_event"] = None
    crawl_state["crawl_task"] = None
    crawl_state["snapshots"] = []
    
    # Start crawl in background and track the task
    task = asyncio.create_task(run_crawl(request))
    crawl_state["crawl_task"] = task
    
    return {"status": "started"}


@app.post("/api/stop")
async def stop_crawl():
    """Stop the current crawl."""
    crawl_state["running"] = False
    
    # Clear 2FA state - this unblocks any waiting 2FA request
    crawl_state["waiting_for_2fa"] = False
    if crawl_state.get("2fa_event"):
        crawl_state["2fa_event"].set()  # Unblock any waiting code
    crawl_state["2fa_code"] = None
    crawl_state["2fa_event"] = None
    
    # Cancel the task if it exists
    task = crawl_state.get("crawl_task")
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    
    crawl_state["crawl_task"] = None
    await broadcast({"type": "stopped"})
    return {"status": "stopped"}


class TwoFACode(BaseModel):
    code: str


@app.post("/api/2fa")
async def submit_2fa_code(data: TwoFACode):
    """Submit a 2FA code."""
    if not crawl_state["waiting_for_2fa"]:
        return JSONResponse({"error": "Not waiting for 2FA code"}, status_code=400)
    
    crawl_state["2fa_code"] = data.code
    if crawl_state["2fa_event"]:
        crawl_state["2fa_event"].set()
    
    return {"status": "submitted"}


async def request_2fa_code(prompt: str) -> str:
    """Request 2FA code from the web interface."""
    crawl_state["waiting_for_2fa"] = True
    crawl_state["2fa_code"] = None
    crawl_state["2fa_event"] = asyncio.Event()
    
    # Notify clients that 2FA is needed
    await broadcast({
        "type": "2fa_required",
        "prompt": prompt,
    })
    
    # Wait for code (with timeout)
    try:
        await asyncio.wait_for(crawl_state["2fa_event"].wait(), timeout=300)  # 5 min timeout
    except asyncio.TimeoutError:
        crawl_state["waiting_for_2fa"] = False
        return ""
    
    crawl_state["waiting_for_2fa"] = False
    return crawl_state["2fa_code"] or ""


async def run_crawl(request: CrawlRequest):
    """Execute the crawl and send updates via WebSocket."""
    try:
        await broadcast({"type": "status", "message": "🚀 Starting crawl...", "phase": "init"})
        
        # Set up 2FA callback for web interface
        set_2fa_callback(request_2fa_code)
        
        # Build config
        config = CrawlConfig(
            start_url=request.url,
            login_url=request.login_url,
            username=request.username,
            password=request.password,
            username_field=request.username_field,
            password_field=request.password_field,
            auth_headers=request.auth_headers,
            cookies=request.cookies,
            max_pages=request.max_pages,
            max_depth=request.max_depth,
            wait_time=request.wait_time,
            headless=request.headless,
            output_dir=str(Path(__file__).parent.parent / "api-docs"),
        )
        
        await broadcast({"type": "status", "message": f"🎯 Target: {request.url}", "phase": "init"})
        
        # Create crawler with custom logging
        crawler = Crawler(config)
        
        # Set up snapshot callback to send to UI
        def snapshot_callback(path: str, url: str, page_num: int):
            filename = Path(path).name
            snapshot_info = {
                "filename": filename,
                "url": url,
                "page_num": page_num,
            }
            crawl_state["snapshots"].append(snapshot_info)
            # Note: Can't await in sync callback, but we can use asyncio.create_task
            asyncio.create_task(broadcast({
                "type": "snapshot",
                "filename": filename,
                "url": url,
                "page_num": page_num,
            }))
        
        crawler.set_snapshot_callback(snapshot_callback)
        
        # Clear previous snapshots
        crawl_state["snapshots"] = []
        
        # Override the crawl to send updates
        original_crawl_page = crawler._crawl_page
        
        async def crawl_page_with_updates(page, url, depth):
            if not crawl_state["running"]:
                return []
            
            await broadcast({
                "type": "page",
                "url": url,
                "depth": depth,
                "visited": len(crawler.visited_urls) + 1,
                "max_pages": config.max_pages,
            })
            
            result = await original_crawl_page(page, url, depth)
            
            # Send captured endpoints
            captured = crawler.interceptor.get_captured_endpoints()
            await broadcast({
                "type": "captured",
                "count": len(captured),
            })
            
            return result
        
        crawler._crawl_page = crawl_page_with_updates
        
        # Run crawl
        await broadcast({"type": "status", "message": "🔐 Setting up authentication...", "phase": "auth"})
        result, captured_endpoints = await crawler.crawl()
        
        if not crawl_state["running"]:
            return
        
        await broadcast({"type": "status", "message": "📊 Analyzing endpoints...", "phase": "analyze"})
        
        # Analyze
        analyzer = EndpointAnalyzer(filter_non_api=True, redact_sensitive=True)
        endpoint_groups = analyzer.analyze(captured_endpoints)
        
        # Store endpoints for UI
        crawl_state["endpoints"] = [
            {
                "method": ep.method.value,
                "path": ep.path_pattern,
                "summary": ep.summary,
                "tags": ep.tags,
                "captured_count": len(ep.captured),
                "responses": list(ep.responses.keys()),
            }
            for ep in endpoint_groups
        ]
        
        await broadcast({
            "type": "endpoints",
            "data": crawl_state["endpoints"],
        })
        
        # Generate docs
        await broadcast({"type": "status", "message": "📝 Generating documentation...", "phase": "docs"})
        
        writer = DocumentationWriter(config.output_dir)
        
        openapi_gen = OpenAPIGenerator()
        spec = openapi_gen.generate(endpoint_groups, config)
        writer.write_openapi(spec)
        
        md_gen = MarkdownGenerator()
        markdown = md_gen.generate(endpoint_groups, config)
        writer.write_markdown(markdown)
        
        writer.write_raw_endpoints(endpoint_groups)
        
        # Complete
        await broadcast({
            "type": "complete",
            "pages_visited": len(result.pages_visited),
            "endpoints_found": len(endpoint_groups),
            "duration": result.duration_seconds,
        })
        
    except asyncio.CancelledError:
        await broadcast({"type": "stopped"})
    except Exception as e:
        await broadcast({
            "type": "error",
            "message": str(e),
        })
    finally:
        crawl_state["running"] = False
        crawl_state["crawl_task"] = None


# ============================================================================
# RECORD MODE ENDPOINTS
# ============================================================================

@app.post("/api/record/start")
async def start_recording(request: RecordRequest):
    """Start record mode with a visible browser."""
    # Close any existing browser first
    if record_state.get("browser"):
        print(f"[Record Mode] Closing existing browser before starting new session")
        try:
            await record_state["browser"].close()
        except Exception as e:
            print(f"[Record Mode] Error closing existing browser: {e}")
        record_state["browser"] = None
        record_state["context"] = None
        record_state["page"] = None
    
    # Cancel any existing task
    if record_state.get("task") and not record_state["task"].done():
        print(f"[Record Mode] Cancelling existing task")
        record_state["task"].cancel()
        try:
            await asyncio.wait_for(record_state["task"], timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    
    # Validate URL
    if not request.url or not request.url.startswith(('http://', 'https://')):
        return JSONResponse({"error": "Invalid URL"}, status_code=400)
    
    print(f"[Record Mode] Starting with URL: {request.url}")
    
    # Reset state
    record_state["recording"] = True
    record_state["captured_endpoints"] = []
    record_state["endpoint_groups"] = {}
    record_state["task"] = None
    
    # Start recording in background
    task = asyncio.create_task(run_recording(request))
    record_state["task"] = task
    
    return {"status": "started", "url": request.url}


@app.post("/api/record/stop")
async def stop_recording():
    """Stop record mode and close browser."""
    record_state["recording"] = False
    
    # Cancel the task
    if record_state.get("task"):
        record_state["task"].cancel()
        try:
            await asyncio.wait_for(record_state["task"], timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
    
    # Close browser
    if record_state.get("browser"):
        try:
            await record_state["browser"].close()
        except:
            pass
    
    record_state["browser"] = None
    record_state["context"] = None
    record_state["page"] = None
    record_state["task"] = None
    
    await broadcast({"type": "record_stopped"})
    return {"status": "stopped"}


@app.get("/api/record/endpoints")
async def get_recorded_endpoints():
    """Get all captured endpoints during recording."""
    return {
        "endpoints": list(record_state["endpoint_groups"].values()),
        "count": len(record_state["endpoint_groups"]),
    }


@app.post("/api/record/endpoint/edit")
async def edit_recorded_endpoint(request: EndpointEditRequest):
    """Edit a captured endpoint (name, description, skip)."""
    endpoint_id = request.endpoint_id
    
    if endpoint_id not in record_state["endpoint_groups"]:
        return JSONResponse({"error": "Endpoint not found"}, status_code=404)
    
    ep = record_state["endpoint_groups"][endpoint_id]
    
    if request.name is not None:
        ep["name"] = request.name
    if request.description is not None:
        ep["description"] = request.description
    if request.skip:
        ep["skipped"] = True
    
    ep["confirmed"] = True
    
    await broadcast({
        "type": "record_endpoint_updated",
        "endpoint": ep,
    })
    
    return {"status": "updated", "endpoint": ep}


@app.post("/api/record/export")
async def export_recorded_docs():
    """Generate documentation from recorded endpoints."""
    if not record_state["endpoint_groups"]:
        return JSONResponse({"error": "No endpoints captured"}, status_code=400)
    
    # Filter out skipped endpoints
    endpoints_to_export = [
        ep for ep in record_state["endpoint_groups"].values()
        if not ep.get("skipped", False)
    ]
    
    if not endpoints_to_export:
        return JSONResponse({"error": "All endpoints were skipped"}, status_code=400)
    
    # Convert to EndpointGroup format for generator
    from src.models import EndpointGroup
    
    groups = []
    for ep in endpoints_to_export:
        # Use user-provided name or auto-generated
        summary = ep.get("name") or ep.get("auto_name", "")
        description = ep.get("description", "")
        
        group = EndpointGroup(
            method=HttpMethod(ep["method"]),
            path_pattern=ep["path"],
            base_url=ep["base_url"],
            summary=summary,
            description=description,
            tags=ep.get("tags", ["General"]),
        )
        groups.append(group)
    
    # Generate documentation
    output_dir = str(Path(__file__).parent.parent / "api-docs")
    writer = DocumentationWriter(output_dir)
    
    # Create a minimal config for the generators
    config = CrawlConfig(
        start_url=record_state.get("start_url", "https://example.com"),
    )
    
    openapi_gen = OpenAPIGenerator()
    spec = openapi_gen.generate(groups, config)
    writer.write_openapi(spec)
    
    md_gen = MarkdownGenerator()
    markdown = md_gen.generate(groups, config)
    writer.write_markdown(markdown)
    
    await broadcast({
        "type": "record_export_complete",
        "endpoints_count": len(groups),
    })
    
    return {
        "status": "exported",
        "endpoints_count": len(groups),
    }


async def run_recording(request: RecordRequest):
    """Run the recording session with visible browser."""
    from playwright.async_api import async_playwright
    
    try:
        print(f"[Record Mode] run_recording called with URL: {request.url}")
        await broadcast({"type": "record_status", "message": f"🚀 Launching browser for {request.url}..."})
        
        record_state["start_url"] = request.url
        
        playwright = await async_playwright().start()
        
        # Launch VISIBLE browser (headless=False)
        browser = await playwright.chromium.launch(
            headless=False,
            args=[
                "--start-maximized",
                "--disable-blink-features=AutomationControlled",
            ]
        )
        record_state["browser"] = browser
        
        # Create context
        context = await browser.new_context(
            viewport=None,  # Use full window size
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        record_state["context"] = context
        
        # Create page
        page = await context.new_page()
        record_state["page"] = page
        
        # Set up request interception
        captured_ids = set()  # Track already captured to avoid duplicates
        
        async def handle_response(response):
            """Capture API responses."""
            if not record_state["recording"]:
                return
            
            try:
                request = response.request
                url = request.url
                
                # Skip non-API requests
                if not _should_capture_request(url, response):
                    return
                
                # Create endpoint ID for deduplication
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path
                method = request.method
                
                # Normalize path for ID
                normalized_path = CapturedEndpoint._normalize_path(path)
                endpoint_id = f"{method}:{normalized_path}"
                
                # Skip if already captured this pattern
                if endpoint_id in captured_ids:
                    return
                
                captured_ids.add(endpoint_id)
                
                # Get response info
                status = response.status
                content_type = response.headers.get("content-type", "")
                
                # Auto-generate name from path
                auto_name = _generate_endpoint_name(method, normalized_path)
                tags = _infer_tags(normalized_path)
                
                # Store endpoint
                endpoint_data = {
                    "id": endpoint_id,
                    "method": method,
                    "path": normalized_path,
                    "original_path": path,
                    "base_url": f"{parsed.scheme}://{parsed.netloc}",
                    "status": status,
                    "content_type": content_type,
                    "auto_name": auto_name,
                    "name": None,  # User can override
                    "description": None,
                    "tags": tags,
                    "confirmed": False,
                    "skipped": False,
                    "captured_at": datetime.now().isoformat(),
                }
                
                record_state["endpoint_groups"][endpoint_id] = endpoint_data
                
                # Broadcast new endpoint
                await broadcast({
                    "type": "record_new_endpoint",
                    "endpoint": endpoint_data,
                })
                
            except Exception as e:
                print(f"Error capturing response: {e}")
        
        # Listen for responses
        page.on("response", handle_response)
        
        await broadcast({"type": "record_status", "message": "🔐 Handling authentication..."})
        
        # Handle login if provided
        if request.login_url and request.username and request.password:
            await page.goto(request.login_url, wait_until="networkidle")
            
            # Find and fill login fields
            username_sel = request.username_field or 'input[type="text"], input[type="email"], input[name*="user"], input[id*="user"]'
            password_sel = request.password_field or 'input[type="password"]'
            
            try:
                await page.fill(username_sel, request.username)
                await page.fill(password_sel, request.password)
                
                # Try to submit
                submit_btn = page.locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")')
                if await submit_btn.count() > 0:
                    await submit_btn.first.click()
                    await page.wait_for_load_state("networkidle")
            except Exception as e:
                print(f"Login automation failed: {e}")
        
        # Navigate to start URL
        print(f"[Record Mode] Navigating to: {request.url}")
        await broadcast({"type": "record_status", "message": f"🌐 Navigating to {request.url}"})
        await page.goto(request.url, wait_until="networkidle")
        print(f"[Record Mode] Successfully loaded: {page.url}")
        
        await broadcast({
            "type": "record_ready",
            "message": "✅ Browser ready! Click around to capture API endpoints.",
        })
        
        # Keep running until stopped
        while record_state["recording"]:
            await asyncio.sleep(1)
            
            # Send heartbeat with current count
            await broadcast({
                "type": "record_heartbeat",
                "endpoints_count": len(record_state["endpoint_groups"]),
            })
        
    except asyncio.CancelledError:
        await broadcast({"type": "record_stopped"})
    except Exception as e:
        await broadcast({"type": "record_error", "message": str(e)})
    finally:
        # Cleanup
        if record_state.get("browser"):
            try:
                await record_state["browser"].close()
            except:
                pass
        record_state["recording"] = False


def _should_capture_request(url: str, response) -> bool:
    """Check if request should be captured as an API endpoint."""
    from urllib.parse import urlparse
    import re
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Skip static assets
    skip_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                       '.woff', '.woff2', '.ttf', '.eot', '.map']
    if any(path.endswith(ext) for ext in skip_extensions):
        return False
    
    # Skip common non-API paths
    skip_patterns = ['/resources/', '/static/', '/assets/', '/_next/', '/sockjs-node/']
    if any(pattern in path for pattern in skip_patterns):
        return False
    
    # Include if it's under /api/
    if '/api/' in path:
        return True
    
    # Include if response is JSON
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        return True
    
    return False


def _generate_endpoint_name(method: str, path: str) -> str:
    """Generate a human-readable name for an endpoint."""
    # Remove common prefixes
    import re
    path = re.sub(r'^/?(api|v\d+)/', '', path)
    
    # Get meaningful parts
    parts = [p for p in path.split("/") if p and not p.startswith("{")]
    
    if not parts:
        resource = "resource"
    else:
        resource = parts[-1].replace("-", " ").replace("_", " ").title()
    
    # Check if it's a single item (has ID param)
    is_single = "{id}" in path
    
    method_actions = {
        "GET": "Get" if is_single else "List",
        "POST": "Create",
        "PUT": "Update",
        "PATCH": "Update",
        "DELETE": "Delete",
    }
    
    action = method_actions.get(method, method)
    return f"{action} {resource}"


def _infer_tags(path: str) -> list:
    """Infer API tags from path."""
    import re
    path = re.sub(r'^/?(api|v\d+)/', '', path)
    parts = [p for p in path.split("/") if p and not p.startswith("{")]
    
    if parts:
        tag = parts[0].replace("-", " ").replace("_", " ").title()
        return [tag]
    return ["General"]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8787)
