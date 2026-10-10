# SentinelAI Local Runner for Windows
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Starting SentinelAI Full Project     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$root = $PSScriptRoot

# 1. Start FastAPI Backend
Write-Host "[1/3] Starting Backend API on http://127.0.0.1:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\backend'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

# 2. Start Celery Worker
Write-Host "[2/3] Starting Celery Worker (Queue: scans)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\backend'; python -m celery -A app.celery_app worker -P solo -l info -Q scans"

# 3. Start Frontend Next.js Dev Server
Write-Host "[3/3] Starting Frontend Web UI on http://localhost:3000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\frontend'; npm run dev"

Write-Host "`nAll services launched! Access the application at: http://localhost:3000" -ForegroundColor Yellow
