#!/bin/bash

# Always work from the repo root so relative paths (.env, ts/, threat-shield/) resolve.
# Uses $0 rather than $BASH_SOURCE so it also works under `sh start.sh` / `zsh start.sh`,
# where BASH_SOURCE is unset and `cd ""` would silently leave us in the caller's directory.
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ] || ! cd "$SCRIPT_DIR"; then
    echo "Error: could not determine the repo root from '$0'"
    exit 1
fi

VENV_DIR="${VENV_DIR:-ts}"

# Kill any existing processes using ports 3000, 5001, 8502, and 8765 (MCP)
kill $(lsof -t -i:3000) 2>/dev/null || true
kill $(lsof -t -i:5001) 2>/dev/null || true
kill $(lsof -t -i:8502) 2>/dev/null || true
kill $(lsof -t -i:8765) 2>/dev/null || true

# Create .env from the template if it doesn't exist yet
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example"
    else
        cat > .env <<'EOF'
# Minimal ThreatShield config — see README.md for the full list
# Provider selection: OPENAI or BEDROCK
LLM_METHOD=OPENAI
OPENAI_API_KEY=
BEDROCK_API_KEY=
GOOGLE_CLIENT_ID=
FLASK_SECRET_KEY=
ALLOWED_ORIGINS=http://localhost:3000
FRONTEND_URL=http://localhost:3000
REACT_APP_DEPLOYMENT_TYPE=dev
REACT_APP_API_URL_DEV=http://localhost:5001/api
EOF
        echo "Created a minimal .env (.env.example not found)"
    fi
    echo "Fill in your credentials in .env, then re-run ./start.sh"
    exit 1
fi

# Load environment variables from .env
export $(cat .env | grep -v '^#' | xargs)

# Check if OPENAI_API_KEY is set (only required when not using BEDROCK)
if [ "${LLM_METHOD}" != "BEDROCK" ] && { [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" = "your-openai-api-key" ]; }; then
    echo "Error: OPENAI_API_KEY not set in .env file"
    exit 1
fi

# Create the virtual environment if it doesn't exist, then activate it
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 not found on PATH"
        exit 1
    fi
    echo "Creating virtual environment in ./$VENV_DIR ..."
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR" || { echo "Error: failed to create virtual environment"; exit 1; }
fi

source "$VENV_DIR/bin/activate" || { echo "Error: failed to activate ./$VENV_DIR"; exit 1; }
echo "Using virtual environment: $VIRTUAL_ENV"

# Install/refresh dependencies whenever requirements.txt changes
REQ_STAMP="$VENV_DIR/.requirements.sha256"
if command -v shasum >/dev/null 2>&1; then
    REQ_HASH=$(shasum -a 256 requirements.txt | awk '{print $1}')
else
    REQ_HASH=$(sha256sum requirements.txt | awk '{print $1}')
fi

if [ "$(cat "$REQ_STAMP" 2>/dev/null)" != "$REQ_HASH" ]; then
    echo "Installing Python dependencies (first run takes a few minutes) ..."
    pip install --upgrade pip
    pip install -r requirements.txt || { echo "Error: pip install failed"; exit 1; }
    echo "$REQ_HASH" > "$REQ_STAMP"
fi

# Sanity-check the venv really has the deps. An interrupted install or a venv
# built by an older script leaves a stamp/dir in place, and app.py would then
# fail with "No module named flask" long after the cause scrolled past.
if ! python3 -c "import flask, httpx" >/dev/null 2>&1; then
    echo "Virtual environment is incomplete — reinstalling dependencies ..."
    pip install -r requirements.txt || { echo "Error: pip install failed"; exit 1; }
    echo "$REQ_HASH" > "$REQ_STAMP"
    python3 -c "import flask, httpx" 2>/dev/null || {
        echo "Error: dependencies still missing after reinstall. Try: rm -rf $VENV_DIR && ./start.sh"
        exit 1
    }
fi
echo "Python: $(command -v python3)"

# Start Flask backend
python3 app.py &

# Wait for Flask to start
sleep 2

# Start MCP server (port 8765)
echo "Starting ThreatShield MCP server on port 8765..."
python3 mcp_server.py &

# Start React frontend (install deps only when missing or the lockfile changed)
echo "Starting React frontend..."
(
    cd threat-shield || exit 1
    if [ ! -d node_modules ] || [ package-lock.json -nt node_modules ]; then
        echo "Installing frontend dependencies ..."
        # npm ci installs exactly what package-lock.json pins — same tree for everyone.
        if ! npm ci; then
            # Last resort: a corrupt/stale lockfile (e.g. EINTEGRITY) would otherwise
            # leave the frontend permanently unstartable. Rebuild it from package.json.
            echo ""
            echo "WARNING: npm ci failed. Moving package-lock.json aside to"
            echo "         package-lock.json.broken and rebuilding from package.json."
            echo "         Resolved versions may differ from the committed lockfile —"
            echo "         diff the two, then commit the new one if it works."
            rm -rf node_modules
            mv package-lock.json package-lock.json.broken 2>/dev/null
            if ! npm install; then
                echo "Error: npm install failed — React frontend not started."
                exit 1
            fi
        fi
    fi
    npm run dev
) &

# Wait for user input
echo "Services running:"
echo "  Flask backend  → http://localhost:5001"
echo "  MCP server     → http://localhost:8765/mcp"
echo "  React frontend → http://localhost:3000"
echo "Press Ctrl+C to stop all servers"
wait
