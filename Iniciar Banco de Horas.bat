@echo off
title Banco de Horas - Ibipora
echo ================================================
echo  Banco de Horas - Prefeitura Municipal de Ibipora
echo ================================================
echo.
cd /d "C:\Users\Leo Assis\OneDrive\Desktop\Claude code\banco_horas"
echo Iniciando sistema em http://localhost:5000
start "" http://localhost:5000
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" app.py
) else (
  python3 app.py
)
pause
