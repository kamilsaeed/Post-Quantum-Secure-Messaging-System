@echo off
echo Starting the application...

echo Starting Backend...
start cmd /k "cd pq_backend && npm start"

echo Starting Frontend...
start cmd /k "cd pq_frontend && npm run dev"

echo Both servers are starting in new windows.
