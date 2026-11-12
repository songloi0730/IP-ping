; Bộ cài IP Finder (Inno Setup 6.5+). Build:  iscc /DAppVersion=1.2.0 installer\ipfinder.iss
; Đầu vào: dist\IPFinder\ (giao diện, PyInstaller onedir) và dist\ipfinder-cli.exe (dòng lệnh, onefile).
; Bộ cài chứa sẵn Python runtime: máy đích KHÔNG cần Internet, KHÔNG cần cài Python.
; Ngôn ngữ bộ cài: English / Tiếng Việt / 中文 (lang\*.isl lấy từ Inno Setup 6.7.1, xem lang\LICENSE-InnoSetup.txt).
;
; Npcap: giấy phép Npcap bản miễn phí không cho phép đóng gói lại, nên bộ cài không chứa Npcap.
; Nếu máy chưa có Npcap, bộ cài tự tìm file npcap-*.exe đặt CÙNG THƯ MỤC với file Setup và chạy nó.

#ifndef AppVersion
  #define AppVersion "1.2.0"
#endif

[Setup]
AppId={{6C1F4E2B-3A57-4C1E-9B7E-2F2D8A1C9E41}
AppName=IP Finder
AppVersion={#AppVersion}
AppVerName=IP Finder {#AppVersion}
AppPublisher=IP Finder
DefaultDirName={autopf}\IP Finder
DefaultGroupName=IP Finder
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=IPFinder-Setup-{#AppVersion}
SetupIconFile=ipfinder.ico
UninstallDisplayIcon={app}\IPFinder.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=6.1sp1
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "vi"; MessagesFile: "lang\Vietnamese.isl"
Name: "zh"; MessagesFile: "lang\ChineseSimplified.isl"

[CustomMessages]
en.DesktopIcon=Create a desktop shortcut
vi.DesktopIcon=Tạo biểu tượng trên Desktop
zh.DesktopIcon=创建桌面快捷方式
en.RunApp=Start IP Finder
vi.RunApp=Chạy IP Finder
zh.RunApp=运行 IP Finder
en.CliName=IP Finder (command line)
vi.CliName=IP Finder (dòng lệnh)
zh.CliName=IP Finder（命令行）
en.ReadmeName=User guide (README)
vi.ReadmeName=Hướng dẫn (README)
zh.ReadmeName=使用说明（README）
en.UninstName=Uninstall IP Finder
vi.UninstName=Gỡ cài đặt IP Finder
zh.UninstName=卸载 IP Finder
en.NpcapFoundAsk=Npcap is not installed on this PC (IP Finder needs it to find devices).%n%nFound the installer:%n%1%n%nInstall Npcap now? (Tick "WinPcap API-compatible Mode" during setup)
vi.NpcapFoundAsk=Máy này chưa có Npcap (IP Finder cần Npcap để dò thiết bị).%n%nĐã tìm thấy bộ cài:%n%1%n%nCài Npcap ngay bây giờ? (Khi cài, tick "WinPcap API-compatible Mode")
zh.NpcapFoundAsk=本机尚未安装 Npcap（IP Finder 需要它来查找设备）。%n%n已找到安装程序：%n%1%n%n现在安装 Npcap 吗？（安装时请勾选“WinPcap API-compatible Mode”）
en.NpcapMissing=Npcap is not installed – IP Finder needs it to find devices.%n%nTo install WITHOUT Internet:%n 1. On a PC with Internet open https://npcap.com/#download and download "Npcap 1.90 installer" (or run Download-Npcap.bat from the offline package).%n 2. Copy npcap-1.90.exe by USB and run it.%n%nTip: put npcap-1.90.exe next to IPFinder-Setup.exe and the setup installs it automatically.
vi.NpcapMissing=Máy này chưa có Npcap – IP Finder cần Npcap để dò thiết bị.%n%nCách cài KHÔNG cần Internet:%n 1. Trên máy có Internet, vào https://npcap.com/#download, tải "Npcap 1.90 installer" (hoặc chạy Download-Npcap.bat trong gói offline).%n 2. Chép npcap-1.90.exe qua USB và chạy file đó.%n%nMẹo: đặt npcap-1.90.exe cạnh IPFinder-Setup.exe, bộ cài sẽ tự cài Npcap.
zh.NpcapMissing=未安装 Npcap —— IP Finder 需要它来查找设备。%n%n无需联网的安装方法：%n 1. 在可上网的电脑上打开 https://npcap.com/#download，下载“Npcap 1.90 installer”（或运行离线包中的 Download-Npcap.bat）。%n 2. 用U盘拷贝 npcap-1.90.exe 并运行。%n%n提示：把 npcap-1.90.exe 放在 IPFinder-Setup.exe 旁边，安装程序会自动安装。
en.NpcapStillMissing=Npcap is still not installed. IP Finder will report an error when scanning until Npcap is installed.
vi.NpcapStillMissing=Npcap vẫn chưa được cài. IP Finder sẽ báo lỗi khi dò cho tới khi cài Npcap.
zh.NpcapStillMissing=Npcap 仍未安装。在安装 Npcap 之前，IP Finder 扫描时会报错。

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"

[Files]
Source: "..\dist\IPFinder\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ipfinder-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "ipfinder.ico"; DestDir: "{app}"; Flags: ignoreversion

[INI]
; Ngôn ngữ chọn lúc cài -> ngôn ngữ mặc định của giao diện (người dùng vẫn đổi được trong chương trình)
Filename: "{app}\ipfinder.ini"; Section: "ui"; Key: "lang"; String: "{language}"; Flags: uninsdeletesection

[Icons]
Name: "{group}\IP Finder"; Filename: "{app}\IPFinder.exe"; IconFilename: "{app}\ipfinder.ico"
Name: "{group}\{cm:CliName}"; Filename: "{cmd}"; Parameters: "/k cd /d ""{app}"" && ipfinder-cli.exe --help"; IconFilename: "{app}\ipfinder.ico"
Name: "{group}\{cm:ReadmeName}"; Filename: "{app}\README.md"
Name: "{group}\{cm:UninstName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\IP Finder"; Filename: "{app}\IPFinder.exe"; IconFilename: "{app}\ipfinder.ico"; Tasks: desktopicon

[UninstallDelete]
Type: files; Name: "{app}\ipfinder.ini"

[Run]
Filename: "{app}\IPFinder.exe"; Description: "{cm:RunApp}"; Flags: nowait postinstall skipifsilent shellexec

[Code]
function NpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'))
    or FileExists(ExpandConstant('{sys}\wpcap.dll'))
    or RegKeyExists(HKLM, 'SOFTWARE\Npcap');
end;

function FindNpcapInstaller: String;
var
  FindRec: TFindRec;
  Dir: String;
begin
  Result := '';
  Dir := ExpandConstant('{src}');
  if FindFirst(Dir + '\npcap*.exe', FindRec) then
  begin
    try
      Result := Dir + '\' + FindRec.Name;
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Installer: String;
  ResultCode: Integer;
begin
  if (CurStep <> ssPostInstall) or NpcapInstalled then
    exit;
  Installer := FindNpcapInstaller;
  if Installer <> '' then
  begin
    if WizardSilent or (MsgBox(FmtMessage(CustomMessage('NpcapFoundAsk'), [Installer]), mbConfirmation, MB_YESNO) = IDYES) then
    begin
      Exec(Installer, '', ExtractFileDir(Installer), SW_SHOW, ewWaitUntilTerminated, ResultCode);
      if not NpcapInstalled then
        MsgBox(CustomMessage('NpcapStillMissing'), mbInformation, MB_OK);
    end;
  end
  else if not WizardSilent then
    MsgBox(CustomMessage('NpcapMissing'), mbInformation, MB_OK);
end;
