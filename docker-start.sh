#!/bin/bash

# Check for .env file
if [ ! -f .env ]; then
    echo "Error: .env file not found"
    exit 1
fi

# Kill any existing processes using ports 80 and 5001
kill $(lsof -t -i:80) 2>/dev/null || true
kill $(lsof -t -i:5001) 2>/dev/null || true

# Start services with docker-compose
sudo docker-compose up --build -d
