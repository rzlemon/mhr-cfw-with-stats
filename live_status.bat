@echo off
title Live Google Apps Script Stats (Updates every 10 sec)
color 0a

:loop
cls
echo ========================================
echo    LIVE Google Apps Script Statistics
echo    Press Ctrl+C to exit
echo ========================================
echo.
python -c "from request_counter import counter; counter.show_status()"
echo.
echo ========================================
echo Updating every 10 seconds...
echo.
timeout /t 10 /nobreak > nul
goto loop