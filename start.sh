#!/bin/bash

# Kill any existing processes using ports 3000, 5001, and 8502
kill $(lsof -t -i:3000) 2>/dev/null || true
kill $(lsof -t -i:5001) 2>/dev/null || true
kill $(lsof -t -i:8502) 2>/dev/null || true

# Load environment variables from .env
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Check if OPENAI_API_KEY is set
if [ -z "$OPENAI_API_KEY" ]; then
    echo "Error: OPENAI_API_KEY not found in .env file"
    exit 1
fi

# Activate the virtual environment if it exists, create if it doesn't
if [ ! -d "env" ]; then
    python3.10 -m venv env
    source env/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source env/bin/activate
fi

# Start Flask backend
python3 app.py &

# Wait for Flask to start
sleep 2

# Start React frontend
echo "Starting React frontend..."
cd threat-shield && npm install && npm run dev &
cd ..

# Wait for user input
echo "Press Ctrl+C to stop all servers"
wait
