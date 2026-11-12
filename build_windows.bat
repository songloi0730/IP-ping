@echo off
REM Build IP Finder cho Windows (can Python 3.8+ x64 va Internet tren MAY BUILD, may dich thi KHONG can).
REM Ket qua: dist\IPFinder-Setup-<ver>.exe (bo cai) va dist\IPFinder\ (ban chay truc tiep).
REM Dung Python 3.8 de file exe chay duoc ca tren Windows 7 SP1.
cd /d "%~dp0"
python -m pip install -r requirements.txt pyinstaller || goto :err
set ICO=%CD%\installer\ipfinder.ico
pyinstaller --noconfirm --clean --onedir --windowed --name IPFinder --icon "%ICO%" --uac-admin --add-data "%ICO%;." --workpath build\gui --specpath build ipfinder_gui.py || goto :err
pyinstaller --noconfirm --clean --onefile --console --name ipfinder-cli --icon "%ICO%" --workpath build\cli --specpath build ipfinder.py || goto :err
dist\ipfinder-cli.exe selftest || goto :err
for /f %%v in ('python -c "import ipfinder; print(ipfinder.__version__)"') do set VER=%%v
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
  echo Chua cai Inno Setup 6 ^(https://jrsoftware.org/isdl.php^) - bo qua buoc tao bo cai.
  echo Ban chay truc tiep nam o dist\IPFinder\IPFinder.exe
  goto :end
)
%ISCC% /DAppVersion=%VER% installer\ipfinder.iss || goto :err
echo.
echo XONG: dist\IPFinder-Setup-%VER%.exe
goto :end
:err
echo BUILD LOI!
:end
pause
