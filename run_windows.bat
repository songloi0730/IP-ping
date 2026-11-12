@echo off
REM Chay IP Finder voi quyen Administrator (chuot phai > Run as administrator)
cd /d "%~dp0"
python ipfinder.py %*
