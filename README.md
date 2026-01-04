# 🔍 API Endpoint Hunter

A powerful tool that crawls websites, intercepts API calls, and automatically generates comprehensive API documentation.

## Features

- **🌐 Deep Web Crawling** - Navigates through websites following links and interactions
- **🔐 Authentication Support** - Handle login forms, cookies, bearer tokens, and custom headers
- **📡 API Interception** - Captures all XHR/Fetch requests with full request/response data
- **📊 Smart Analysis** - Detects REST patterns, GraphQL queries, and infers data schemas
- **📚 Auto Documentation** - Generates OpenAPI 3.0 specs and beautiful Markdown docs

## Installation

```bash
# Clone and navigate to the project
cd "API Endpoint Hunter"

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

## Quick Start

### Basic Usage (No Auth)

```bash
python hunter.py crawl https://example.com
```

### With Login Credentials

```bash
python hunter.py crawl https://example.com \
  --login-url https://example.com/login \
  --username myuser \
  --password mypass
```

### With Bearer Token

```bash
python hunter.py crawl https://example.com \
  --auth-header "Authorization: Bearer your-token-here"
```

### With Cookies

```bash
python hunter.py crawl https://example.com \
  --cookie "session=abc123" \
  --cookie "auth_token=xyz789"
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--login-url` | URL of the login page |
| `--username` | Username for login form |
| `--password` | Password for login form |
| `--username-field` | CSS selector for username input (default: auto-detect) |
| `--password-field` | CSS selector for password input (default: auto-detect) |
| `--auth-header` | Custom auth header (can be used multiple times) |
| `--cookie` | Cookie to set (can be used multiple times) |
| `--max-pages` | Maximum pages to crawl (default: 50) |
| `--max-depth` | Maximum link depth (default: 3) |
| `--output` | Output directory (default: ./api-docs) |
| `--format` | Output format: openapi, markdown, both (default: both) |
| `--headless` | Run browser in headless mode (default: true) |
| `--wait-time` | Wait time after page load in ms (default: 2000) |

## Output

The tool generates:

1. **`openapi.yaml`** - Full OpenAPI 3.0 specification
2. **`api-docs.md`** - Human-readable Markdown documentation
3. **`endpoints.json`** - Raw captured endpoint data

## Examples

### Crawl a SPA with JWT Auth

```bash
python hunter.py crawl https://app.example.com \
  --auth-header "Authorization: Bearer eyJhbG..." \
  --max-pages 100 \
  --wait-time 3000
```

### Crawl with Form Login

```bash
python hunter.py crawl https://dashboard.example.com \
  --login-url https://dashboard.example.com/auth/login \
  --username admin@example.com \
  --password secretpass \
  --username-field "#email" \
  --password-field "#password"
```

## How It Works

1. **Browser Automation** - Uses Playwright to control a real browser
2. **Network Interception** - Hooks into browser network layer to capture all API calls
3. **Smart Crawling** - Follows links, triggers buttons, and explores the site
4. **Schema Inference** - Analyzes request/response bodies to infer data types
5. **Doc Generation** - Produces standardized OpenAPI specs and readable docs

## License

MIT License - Use freely for your projects!
