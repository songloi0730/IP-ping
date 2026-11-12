; Bộ cài IP Finder (Inno Setup 6). Build:  iscc /DAppVersion=1.1.0 installer\ipfinder.iss
; Đầu vào: dist\IPFinder\ (giao diện, PyInstaller onedir) và dist\ipfinder-cli.exe (dòng lệnh, onefile).
; Bộ cài chứa sẵn Python runtime, KHÔNG cần Internet, KHÔNG cần cài Python.
;
; Npcap: giấy phép Npcap bản miễn phí không cho phép đóng gói lại, nên bộ cài không chứa Npcap.
; Nếu máy chưa có Npcap, bộ cài tự tìm file npcap-*.exe đặt CÙNG THƯ MỤC với file Setup và chạy nó.

#ifndef AppVersion
  #define AppVersion "1.1.0"
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

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
en.DesktopIcon=Tạo biểu tượng trên Desktop
en.RunApp=Chạy IP Finder
en.NpcapFoundAsk=Máy này chưa có Npcap (IP Finder cần Npcap để dò thiết bị).%n%nĐã tìm thấy bộ cài:%n%1%n%nCài Npcap ngay bây giờ? (Khi cài, tick "WinPcap API-compatible Mode")
en.NpcapMissing=Máy này chưa có Npcap – IP Finder cần Npcap để dò thiết bị.%n%nCách cài KHÔNG cần Internet:%n 1. Trên máy có Internet, tải npcap-x.yz.exe tại https://npcap.com (hoặc dùng bộ cài Wireshark – có kèm Npcap).%n 2. Chép qua USB và chạy file đó.%n%nMẹo: đặt file npcap-x.yz.exe cùng thư mục với IPFinder-Setup.exe, lần cài sau bộ cài sẽ tự cài Npcap.
en.NpcapStillMissing=Npcap vẫn chưa được cài. IP Finder sẽ báo lỗi khi dò cho tới khi cài Npcap.

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"

[Files]
Source: "..\dist\IPFinder\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\ipfinder-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "ipfinder.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\IP Finder"; Filename: "{app}\IPFinder.exe"; IconFilename: "{app}\ipfinder.ico"
Name: "{group}\IP Finder (dòng lệnh)"; Filename: "{cmd}"; Parameters: "/k cd /d ""{app}"" && ipfinder-cli.exe --help"; IconFilename: "{app}\ipfinder.ico"
Name: "{group}\Hướng dẫn (README)"; Filename: "{app}\README.md"
Name: "{group}\Gỡ cài đặt IP Finder"; Filename: "{uninstallexe}"
Name: "{autodesktop}\IP Finder"; Filename: "{app}\IPFinder.exe"; IconFilename: "{app}\ipfinder.ico"; Tasks: desktopicon

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
