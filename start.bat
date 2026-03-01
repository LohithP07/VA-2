@echo off
title Veracity Agent Launcher
color 0A

echo ============================================
echo   Veracity Agent v2.0 - Launcher
echo ============================================
echo.
echo  Select which frontend to launch:
echo.
echo  [1] React-style HTML Frontend (NEW - Blue/White/Black UI)
echo  [2] Streamlit Dashboard (Legacy)
echo  [3] Both
echo.
set /p choice="Enter 1, 2 or 3 (default 1): "
if "%choice%"=="" set choice=1

:: Set working directory to this file's location
cd /d "%~dp0"

:: Check venv exists
if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found.
    echo Please run:  python -m venv venv
    echo Then:        pip install -r req.txt
    pause
    exit /b 1
)

echo.
echo [1/2] Starting Backend API (FastAPI + Uvicorn)...
start "Veracity - Backend API" cmd /k "title Veracity Backend && color 0B && call venv\Scripts\activate.bat && uvicorn backend.main:app --reload"

:: Small delay so backend can start
timeout /t 3 /nobreak >nul

if "%choice%"=="2" goto streamlit
if "%choice%"=="3" goto both

:html_frontend
echo [2/2] Opening HTML Frontend...
timeout /t 2 /nobreak >nul
start "" "frontend\index.html"
goto done

:streamlit
echo [2/2] Starting Streamlit Dashboard...
start "Veracity - Dashboard" cmd /k "title Veracity Dashboard && color 05 && call venv\Scripts\activate.bat && streamlit run dashboard/app.py"
timeout /t 4 /nobreak >nul
goto done

:both
echo [2/3] Starting Streamlit Dashboard...
start "Veracity - Dashboard" cmd /k "title Veracity Dashboard && color 05 && call venv\Scripts\activate.bat && streamlit run dashboard/app.py"
timeout /t 2 /nobreak >nul
echo [3/3] Opening HTML Frontend...
start "" "frontend\index.html"
goto done

:done
echo.
echo ============================================
echo   Services are now running!
echo.
echo   Backend API   : http://127.0.0.1:8000
echo   HTML Frontend : frontend\index.html
echo   Streamlit     : http://localhost:8501 (if chosen)
echo   API Docs      : http://127.0.0.1:8000/docs
echo.
echo   HTML Pages:
echo     Landing  : frontend/index.html
echo     Login    : frontend/login.html
echo     Register : frontend/register.html
echo     Dashboard: frontend/dashboard.html
echo.
echo   Close terminal windows to stop services.
echo ============================================
echo.
pause
