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

from src.models import CrawlConfig
from src.crawler import Crawler
from src.analyzer import EndpointAnalyzer
from src.generator import DocumentationWriter, MarkdownGenerator, OpenAPIGenerator
from src.auth import set_2fa_callback

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
}


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


# WebSocket connections for live updates
connected_clients: list[WebSocket] = []


async def broadcast(message: dict):
    """Send message to all connected clients."""
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            pass


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


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


@app.post("/api/crawl")
async def start_crawl(request: CrawlRequest):
    """Start a new crawl."""
    if crawl_state["running"]:
        return JSONResponse({"error": "A crawl is already in progress"}, status_code=400)
    
    # Reset state
    crawl_state["running"] = True
    crawl_state["progress"] = []
    crawl_state["result"] = None
    crawl_state["endpoints"] = []
    
    # Start crawl in background
    asyncio.create_task(run_crawl(request))
    
    return {"status": "started"}


@app.post("/api/stop")
async def stop_crawl():
    """Stop the current crawl."""
    crawl_state["running"] = False
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
        analyzer = EndpointAnalyzer()
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
        
    except Exception as e:
        await broadcast({
            "type": "error",
            "message": str(e),
        })
    finally:
        crawl_state["running"] = False


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8787)
