; RackTrace（機房線路對應圖）安裝程式
; 把 netmap.exe 裝到 Program Files，註冊成「開機自動啟動、不用登入」的背景服務（工作排程器，SYSTEM 執行），
; 資料放在 C:\ProgramData\netmap（只有系統管理員能讀）；升級不會動資料，解除安裝時問你要不要一併刪除資料。
; 編譯：iscc /DAppVer=1.17.0 /DSrcDir=..\dist-dir\netmap RackTrace.iss
#ifndef AppVer
  #define AppVer "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "..\dist-dir\netmap"
#endif

[Setup]
AppId={{6F0B4E6A-2B1D-4C57-9D0E-7A3C5B9A1E42}
AppName=RackTrace 機房線路對應圖
AppVersion={#AppVer}
VersionInfoVersion={#AppVer}.0
VersionInfoProductVersion={#AppVer}.0
AppPublisher=RackTrace
DefaultDirName={autopf}\RackTrace
DefaultGroupName=RackTrace
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=RackTrace-Setup
SetupIconFile=..\netmap.ico
UninstallDisplayIcon={app}\netmap.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Languages]
#ifexist "ChineseTraditional.isl"
Name: "zht"; MessagesFile: "ChineseTraditional.isl"
#else
Name: "en"; MessagesFile: "compiler:Default.isl"
#endif

[CustomMessages]
#ifexist "ChineseTraditional.isl"
zht.TaskAuto=開機自動啟動（不用登入）
zht.TaskFw=允許公司內網的其他電腦用瀏覽器連進來（在 Windows 防火牆開放，只限私人／網域網路）
zht.TaskDesk=在桌面建立捷徑
zht.OpenNow=現在開啟 RackTrace
zht.KeepData=要連同資料（設備圖、歷史紀錄、帳密）一起刪除嗎？%n%n選「否」會保留在 C:\ProgramData\netmap，之後重新安裝就能接著用。
#else
en.TaskAuto=Start automatically at boot (no sign-in needed)
en.TaskFw=Allow other computers on the internal network to connect (Windows Firewall, private/domain only)
en.TaskDesk=Create a desktop shortcut
en.OpenNow=Open RackTrace now
en.KeepData=Also delete the data (maps, history, credentials)?%n%nChoose No to keep it in C:\ProgramData\netmap.
#endif

[Tasks]
Name: "autostart"; Description: "{cm:TaskAuto}"; GroupDescription: "服務 / Service"
Name: "firewall"; Description: "{cm:TaskFw}"; GroupDescription: "服務 / Service"
Name: "desktopicon"; Description: "{cm:TaskDesk}"; GroupDescription: "捷徑 / Shortcuts"; Flags: unchecked

[Files]
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "install-task.ps1"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; 升級時先清掉舊的程式資料夾，避免殘留舊版檔案
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\RackTrace"; Filename: "{app}\netmap.exe"; Parameters: "--open"; IconFilename: "{app}\netmap.exe"
Name: "{autoprograms}\RackTrace 管理視窗"; Filename: "{app}\netmap.exe"; Parameters: "--gui"; IconFilename: "{app}\netmap.exe"
Name: "{autodesktop}\RackTrace"; Filename: "{app}\netmap.exe"; Parameters: "--open"; Tasks: desktopicon

[Run]
; 1) 把這個使用者原本的資料（%APPDATA%\netmap）複製到共用資料夾，並把密碼改成「這台電腦」加密（已經有資料就不動）
Filename: "{app}\netmap.exe"; Parameters: "--migrate-user-data"; Flags: runhidden runasoriginaluser waituntilterminated
; 2) 共用資料夾只留給系統管理員和 SYSTEM（裡面有 SNMP／SSH 帳密）
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\netmap"" /inheritance:r /grant:r ""SYSTEM:(OI)(CI)F"" ""*S-1-5-32-544:(OI)(CI)F"" /C /Q"; Flags: runhidden waituntilterminated; Check: DirExists(ExpandConstant('{commonappdata}\netmap'))
; 裡面的檔案改成「繼承」資料夾的權限（不能對檔案逐一移除繼承，否則可能變成誰都打不開）
Filename: "{sys}\icacls.exe"; Parameters: """{commonappdata}\netmap\*"" /reset /T /C /Q"; Flags: runhidden waituntilterminated; Check: DirExists(ExpandConstant('{commonappdata}\netmap'))
; 3) 防火牆
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""RackTrace"""; Flags: runhidden waituntilterminated; Tasks: firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""RackTrace"" dir=in action=allow program=""{app}\netmap.exe"" enable=yes profile=private,domain"; Flags: runhidden waituntilterminated; Tasks: firewall
; 4) 開機自動啟動 + 立刻啟動
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-task.ps1"" -Exe ""{app}\netmap.exe"""; Flags: runhidden waituntilterminated; Tasks: autostart
Filename: "{app}\netmap.exe"; Parameters: "--open"; Description: "{cm:OpenNow}"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-task.ps1"" -Exe ""{app}\netmap.exe"" -Remove"; Flags: runhidden waituntilterminated; RunOnceId: "RtTask"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM netmap.exe"; Flags: runhidden waituntilterminated; RunOnceId: "RtKill"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""RackTrace"""; Flags: runhidden waituntilterminated; RunOnceId: "RtFw"

[Code]
// 安裝／升級前先停掉執行中的服務和程式，才能覆蓋 netmap.exe
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "RackTrace"', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM netmap.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(1500);
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DeleteFile(ExpandConstant('{commonappdata}\netmap.url'));
    if (not UninstallSilent) and DirExists(ExpandConstant('{commonappdata}\netmap')) then
      if MsgBox(CustomMessage('KeepData'), mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant('{commonappdata}\netmap'), True, True, True);
  end;
end;
