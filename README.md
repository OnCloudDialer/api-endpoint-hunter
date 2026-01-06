# 🔍 API Endpoint Hunter

A powerful tool that crawls websites, intercepts API calls, and automatically generates comprehensive API documentation.

## Features

- **🌐 Deep Web Crawling** - Navigates through websites following links and interactions
- **🔴 Record Mode** - Interactive mode with visible browser for manual API capture
- **🔐 Authentication Support** - Handle login forms, 2FA, cookies, bearer tokens, and custom headers
- **📡 API Interception** - Captures all XHR/Fetch requests with full request/response data
- **📊 Smart Analysis** - Detects REST patterns, infers schemas, redacts sensitive data
- **📚 Auto Documentation** - Generates OpenAPI 3.0 specs and beautiful Markdown docs
- **🔒 Security** - Automatic credential redaction in generated docs

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

## 🖥️ Web Interface (Recommended)

The easiest way to use API Endpoint Hunter is through the web interface:

```bash
python run_web.py
```

Then open [http://127.0.0.1:8787](http://127.0.0.1:8787) in your browser.

### Two Modes Available:

#### 🕷️ Auto Crawl Mode
- Enter URL and optional credentials
- Tool automatically crawls the site
- Captures all API endpoints
- Generates documentation

#### 🔴 Record Mode (NEW!)
- Opens a **visible browser window**
- **You click around** the site manually  
- APIs captured in **real-time** as you navigate
- **Name and describe** each endpoint as it's captured
- **Skip** unwanted endpoints
- Export documentation when done

### Record Mode Flow:

1. Click **"🔴 Record Mode"** tab
2. Enter the start URL (and optional login credentials)
3. Click **"🔴 Start Recording"** - browser window opens
4. Navigate the site - click buttons, menus, pages
5. For each new API endpoint:
   - Modal appears with auto-generated name
   - Edit the name/description or skip
   - Press **Enter** to confirm, **Escape** to cancel
6. Click **"📄 Export Documentation"** when done
7. Download OpenAPI spec and Markdown docs

## Command Line Usage

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
| `--profile` | Load a saved configuration profile |
| `--save-as` | Save current config as a named profile |

## Profile Management

Save and reuse configurations:

```bash
# Save a profile
python hunter.py crawl https://example.com --username admin --password secret --save-as myprofile

# Use a saved profile
python hunter.py crawl --profile myprofile

# List profiles
python hunter.py profiles list

# Delete a profile  
python hunter.py profiles delete myprofile
```

## Output

The tool generates:

1. **`openapi.yaml`** - Full OpenAPI 3.0 specification
2. **`api-docs.md`** - Human-readable Markdown documentation
3. **`endpoints.json`** - Raw captured endpoint data
4. **`snapshots/`** - Screenshots taken during crawl

## Smart Features

### 🔒 Credential Redaction
Passwords, tokens, and secrets are automatically replaced with `***REDACTED***` in generated docs.

### 📝 Path Parameterization
IDs in URLs are automatically converted to parameters:
- `/api/users/12345` → `/api/users/{id}`
- `/Device/Detail/PD_KYVFC6Y00955` → `/Device/Detail/{id}`

### 🚫 Non-API Filtering
Static assets and resource files are automatically excluded:
- `/resources/`, `/static/`, `/assets/`
- `.js`, `.css`, `.png`, `.jpg`, etc.

### 📅 Timestamp Detection
Unix timestamps are detected and documented:
```yaml
date:
  type: integer
  description: "Unix timestamp in milliseconds"
```

## How It Works

1. **Browser Automation** - Uses Playwright to control a real Chromium browser
2. **Network Interception** - Hooks into browser network layer to capture all API calls
3. **Smart Crawling** - Follows links, clicks buttons, explores the site
4. **2FA Support** - Pauses for manual 2FA entry when detected
5. **Schema Inference** - Analyzes request/response bodies to infer data types
6. **Security Processing** - Redacts credentials, filters non-APIs, parameterizes paths
7. **Doc Generation** - Produces standardized OpenAPI specs and readable docs

## License

MIT License - Use freely for your projects!
