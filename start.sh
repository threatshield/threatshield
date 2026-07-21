#!/bin/bash

# Kill any existing processes using ports 3000, 5001, 8502, and 8765 (MCP)
kill $(lsof -t -i:3000) 2>/dev/null || true
kill $(lsof -t -i:5001) 2>/dev/null || true
kill $(lsof -t -i:8502) 2>/dev/null || true
kill $(lsof -t -i:8765) 2>/dev/null || true

# Load environment variables from .env
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Check if OPENAI_API_KEY is set (only required when not using BEDROCK)
if [ "${LLM_METHOD}" != "BEDROCK" ] && [ -z "$OPENAI_API_KEY" ]; then
    echo "Error: OPENAI_API_KEY not found in .env file"
    exit 1
fi

# Activate the virtual environment if it exists, create if it doesn't
if [ ! -d "ts" ]; then
    python3 -m venv ts
    source ts/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source ts/bin/activate
fi

# Start Flask backend
python3 app.py &

# Wait for Flask to start
sleep 2

# Start MCP server (port 8765)
echo "Starting ThreatShield MCP server on port 8765..."
python3 mcp_server.py &

# Start React frontend
echo "Starting React frontend..."
cd threat-shield && npm install && npm run dev &
cd ..

# Wait for user input
echo "Services running:"
echo "  Flask backend  → http://localhost:5001"
echo "  MCP server     → http://localhost:8765/mcp"
echo "  React frontend → http://localhost:3000"
echo "Press Ctrl+C to stop all servers"
wait
