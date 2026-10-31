; ============================================================================
;  Aether Desktop - Inno Setup 6 script
;  ویزارد گرافیکی مدرن (WizardStyle=modern)، دوزبانه (EN/FA)، Uninstaller کامل.
;  همهٔ مقادیر از طریق /D توسط GitHub Actions تزریق می‌شوند — هیچ دخالت دستی.
; ============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "1.4.0"
#endif
#ifndef MyArch
  #define MyArch "x64"
#endif
#ifndef PayloadDir
  #define PayloadDir "..\dist\payload-x64"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define MyAppName        "Aether"
#define MyAppPublisher   "Cluvex Studio"
#define MyAppURL         "https://github.com/YOUR-ORG/AetherDesktop"
#define MyAppExeName     "Aether.exe"
; GUID ثابت: تضمین می‌کند نسخهٔ جدید روی قبلی ارتقا داده شود، نه نصب دوم.
; همان نقشی که پایداری keystore در اندروید دارد. هرگز تغییرش ندهید.
#define MyAppId          "{{8B1F5B2E-7C41-4B8A-9E33-AE7C1D9F2A10}"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
VersionInfoVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir={#OutputDir}
OutputBaseFilename=Aether-Setup-{#MyAppVersion}-{#MyArch}
SetupIconFile=..\src-tauri\icons\icon.ico

; ---- معماری سیستم ----------------------------------------------------
; برای x64 فقط روی ویندوز ۶۴بیتی نصب می‌شود و در Program Files واقعی؛
; نسخهٔ x86 روی هر دو نصب می‌شود.
#if MyArch == "x64"
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif

PrivilegesRequired=admin
; security-audit-1.3.0 (S-06): no per-user install; the app runs elevated and
; must never live in a user-writable folder.
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
MinVersion=10.0.17763
DisableWelcomePage=no
DisableProgramGroupPage=yes
AllowNoIcons=yes
ShowLanguageDialog=auto
CloseApplications=force
RestartApplications=no
SetupMutex=AetherSetupMutex
AppMutex=AetherAppMutex

; ---- ظاهر حرفه‌ای -------------------------------------------------------
WizardStyle=modern
WizardSizePercent=120
WizardResizable=yes
WizardImageFile=wizard-large.bmp
WizardSmallImageFile=wizard-small.bmp
WizardImageStretch=yes
LicenseFile=LICENSE.rtf
InfoBeforeFile=
SetupLogging=yes

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "fa"; MessagesFile: "Persian.isl"

[Tasks]
Name: "desktopicon";  Description: "{cm:CreateDesktopIcon}";  GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "startupicon";  Description: "{cm:AutoStartProgram,{#MyAppName}}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "firewall";     Description: "{cm:FirewallRule}";        GroupDescription: "{cm:SystemIntegration}"

[Files]
; کل خروجی بیلد (Aether.exe + engine\aether.exe + engine\wintun.dll + منابع)
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}";                Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";          Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}";          Filename: "{app}\{#MyAppExeName}"; Parameters: "--minimized"; Tasks: startupicon

[Run]
; قاعدهٔ فایروال — معادل درخواست مجوز VpnService در اندروید.
Filename: "{sys}\netsh.exe"; \
  Parameters: "advfirewall firewall add rule name=""Aether"" dir=in action=allow program=""{app}\{#MyAppExeName}"" enable=yes"; \
  Flags: runhidden waituntilterminated; Tasks: firewall; StatusMsg: "{cm:ConfiguringFirewall}"

; ShellExecute is required here. CreateProcess cannot launch a requireAdministrator
; EXE from the already-elevated installer and returns ERROR_ELEVATION_REQUIRED (740).
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; \
  Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aether"""; Flags: runhidden; RunOnceId: "DelFwRule"
; v1.2.0 — قواعد گارد نشتی WebRTC هم باید با حذف برنامه پاک شوند.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aether Leak Guard"""; Flags: runhidden; RunOnceId: "DelLeakGuardRules"
; v1.2.0 — remove persistent browser/IPv6 kill-switch rules on uninstall.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aether Kill Switch"""; Flags: runhidden; RunOnceId: "DelKillSwitchRules"

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\Aether\logs"
Type: dirifempty;     Name: "{localappdata}\Aether"

[CustomMessages]
en.FirewallRule=Allow Aether through Windows Firewall (recommended)
en.SystemIntegration=System integration:
en.ConfiguringFirewall=Configuring Windows Firewall...
en.KeepSettings=Keep my settings and diagnostics logs
fa.FirewallRule=اجازهٔ عبور Aether از فایروال ویندوز (توصیه‌شده)
fa.SystemIntegration=یکپارچگی با سیستم:
fa.ConfiguringFirewall=در حال پیکربندی فایروال ویندوز...
fa.KeepSettings=تن��یمات و لاگ‌های من حفظ شود

[Code]
var
  KeepSettingsPage: TInputOptionWizardPage;

{ صفحهٔ اختیاری پاکسازی هنگام حذف نصب — دقیقاً رفتار نرم‌افزارهای بزرگ }
function InitializeUninstall(): Boolean;
begin
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { مهم: در حذف بی‌صدا (/VERYSILENT) هرگز نباید پنجرهٔ سؤال باز شود.
      MsgBox های داخل [Code] با /SUPPRESSMSGBOXES سرکوب نمی‌شوند و همین
      باعث می‌شد تست CI بی‌نهایت منتظر بماند. در حالت بی‌صدا،
      تنظیمات کاربر نگه داشته می‌شود (امن‌ترین انتخاب). }
    if not UninstallSilent then
    begin
      if MsgBox(ExpandConstant('{cm:KeepSettings}'), mbConfirmation, MB_YESNO) = IDNO then
        DelTree(ExpandConstant('{localappdata}\Aether'), True, True, True);
    end;
  end;
end;

{ پیش‌نیاز: WebView2. در ویندوز 11 و ویندوز 10 به‌روز از پیش نصب است؛
  در غیر این صورت bootstrapper رسمی مایکروسافت بی‌صدا اجرا می‌شود. }
function WebView2Installed(): Boolean;
var
  V: String;
begin
  Result :=
    RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V) or
    RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', V);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if not WebView2Installed() then
  begin
    if FileExists(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe')) then
      Exec(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install',
           '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
