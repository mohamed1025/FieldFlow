@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   Syntrix ServiceOps
echo   Existing Supabase database connection
echo ==========================================
where node >nul 2>nul || (echo Node.js 22+ is required. Install from https://nodejs.org/ && pause && exit /b 1)
where npm >nul 2>nul || (echo npm was not found. Reinstall Node.js. && pause && exit /b 1)
if not exist .env (
  copy .env.example .env >nul
  echo Created .env. Add your existing DATABASE_URL and Supabase SSL settings before continuing.
  notepad .env
  pause
)
if not exist node_modules (
  echo Installing dependencies. This requires internet access...
  call npm install
  if errorlevel 1 (echo npm install failed. Check the internet connection and try again. && pause && exit /b 1)
)
echo Starting ServiceOps. The existing database will be used; no seed or reset will run.
start "Syntrix ServiceOps" cmd /k "npm run dev"
timeout /t 5 >nul
start http://localhost:5173
