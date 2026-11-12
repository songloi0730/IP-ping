@echo off
chcp 65001 >nul
REM ======================================================================
REM  Chay tren may CO INTERNET: tai Npcap vao thu muc nay.
REM  Run on a PC WITH INTERNET: downloads Npcap into this folder.
REM  在可上网的电脑上运行：将 Npcap 下载到本文件夹。
REM ======================================================================
set NPCAP_VER=1.90
cd /d "%~dp0"
if exist "npcap-%NPCAP_VER%.exe" (
  echo npcap-%NPCAP_VER%.exe da co / already here / 已存在
  goto :done
)
echo Dang tai / Downloading / 正在下载 npcap-%NPCAP_VER%.exe ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -UseBasicParsing -Uri 'https://npcap.com/dist/npcap-%NPCAP_VER%.exe' -OutFile 'npcap-%NPCAP_VER%.exe'; exit 0 } catch { Write-Host $_.Exception.Message; exit 1 }"
if errorlevel 1 (
  echo.
  echo Khong tai duoc tu dong. Hay tai "Npcap %NPCAP_VER% installer" bang trinh duyet, luu vao thu muc nay.
  echo Automatic download failed. Download "Npcap %NPCAP_VER% installer" in the browser and save it here.
  echo 自动下载失败。请在浏览器中下载 "Npcap %NPCAP_VER% installer" 并保存到本文件夹。
  start "" "https://npcap.com/#download"
  goto :done
)
echo OK: npcap-%NPCAP_VER%.exe
:done
echo.
echo Giu file npcap cung thu muc voi IPFinder-Setup.exe roi chep sang may dich bang USB.
echo Keep the npcap file next to IPFinder-Setup.exe and copy the folder to the target PC by USB.
echo 请将 npcap 文件与 IPFinder-Setup.exe 放在同一文件夹，再用U盘拷贝到目标电脑。
pause
