#!/usr/bin/env python3
"""Launch the API Endpoint Hunter web interface."""

import uvicorn

if __name__ == "__main__":
    print("\n🔍 API Endpoint Hunter - Web Interface")
    print("=" * 40)
    print("Starting server at http://127.0.0.1:8787")
    print("Press Ctrl+C to stop\n")
    
    uvicorn.run(
        "web.app:app",
        host="127.0.0.1",
        port=8787,
        reload=False,
        log_level="warning",
    )
