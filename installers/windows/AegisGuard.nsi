; ==============================================================================
;  Aegis-Guard Enterprise Security Suite - NSIS Installer Script
;  Standard Windows Installer (Nullsoft Scriptable Install System)
; ==============================================================================

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

Name "Aegis-Guard"
OutFile "..\dist\AegisGuard-Setup-NSIS-x64.exe"
InstallDir "$PROGRAMFILES64\Aegis-Guard"
InstallDirRegKey HKLM "Software\Aegis-Guard" "Install_Dir"
RequestExecutionLevel admin

; Modern UI settings
!define MUI_ABORTWARNING
!define MUI_ICON "..\resources\icons\icon.ico"
!define MUI_UNICON "..\resources\icons\icon.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\aegis-guard.exe"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Aegis-Guard Core Engine & GUI" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  
  ; Stop services if updating
  nsExec::Exec 'net stop AegisProcessEngine'
  nsExec::Exec 'taskkill /F /IM aegis-guard.exe'

  ; Binaries
  File /nonfatal "..\target\release\aegis-guard.exe"
  File /nonfatal "..\target\release\aegis-process-engine.exe"
  File /nonfatal "..\target\release\aegis-network-observer.exe"
  
  ; Resources
  SetOutPath "$INSTDIR\resources"
  File /r "..\resources\*.*"
  
  ; Data directories
  CreateDirectory "$COMMONAPPDATA\Aegis-Guard\quarantine"
  CreateDirectory "$COMMONAPPDATA\Aegis-Guard\sandbox"
  CreateDirectory "$COMMONAPPDATA\Aegis-Guard\logs"
  
  ; Write registry
  WriteRegStr HKLM "Software\Aegis-Guard" "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "DisplayName" "Aegis-Guard Endpoint Security"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "DisplayIcon" "$INSTDIR\resources\icons\icon.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "Publisher" "Aegis Security Research"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "DisplayVersion" "1.0.0"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard" "NoRepair" 1
  
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Start Menu & Desktop Shortcuts" SecShortcuts
  CreateDirectory "$SMPROGRAMS\Aegis-Guard"
  CreateShortcut "$SMPROGRAMS\Aegis-Guard\Aegis-Guard.lnk" "$INSTDIR\aegis-guard.exe" "" "$INSTDIR\resources\icons\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\Aegis-Guard\Uninstall Aegis-Guard.lnk" "$INSTDIR\uninstall.exe"
  CreateShortcut "$DESKTOP\Aegis-Guard.lnk" "$INSTDIR\aegis-guard.exe" "" "$INSTDIR\resources\icons\icon.ico" 0
SectionEnd

Section "Register Windows Background Service" SecService
  nsExec::Exec 'sc.exe create AegisProcessEngine binPath= "$INSTDIR\aegis-process-engine.exe" start= auto DisplayName= "Aegis-Guard Real-Time Process Monitor"'
  nsExec::Exec 'sc.exe start AegisProcessEngine'
  nsExec::Exec 'netsh advfirewall firewall add rule name="Aegis-Guard IDS Observer" dir=in action=allow program="$INSTDIR\aegis-network-observer.exe" enable=yes'
SectionEnd

Section "Uninstall"
  nsExec::Exec 'sc.exe stop AegisProcessEngine'
  nsExec::Exec 'sc.exe delete AegisProcessEngine'
  nsExec::Exec 'netsh advfirewall firewall delete rule name="Aegis-Guard IDS Observer"'

  Delete "$DESKTOP\Aegis-Guard.lnk"
  RMDir /r "$SMPROGRAMS\Aegis-Guard"
  RMDir /r "$INSTDIR"
  
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Aegis-Guard"
  DeleteRegKey HKLM "Software\Aegis-Guard"
SectionEnd
