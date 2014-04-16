!include "MUI.nsh"
!include x64.nsh

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!define PRODUCT_NAME "encrypt"
!define PRODUCT_VERSION "2014.00"
!define PRODUCT_PUBLISHER "albinoloverats ~ Software Development"
!define PRODUCT_WEB_SITE "https://albinoloverats.net/projects/encrypt"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\encrypt.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define EXPLORER_CONTEXT "*\shell\Encrypt/Decrypt\command"

SetCompressor lzma
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${PRODUCT_NAME}-${PRODUCT_VERSION}-install.exe"
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ComponentText "Check the components you want to install and uncheck the components you don't want to install:"
ShowInstDetails show
ShowUnInstDetails show

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "docs\LICENCE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

Function .onInit
  ReadRegStr $R0 HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"
  StrCmp $R0 "" done

  MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
  "${PRODUCT_NAME} is already installed. $\n$\nClick `OK` to remove the \
  previous version or `Cancel` to cancel this upgrade." \
  IDOK uninst
  Abort

  uninst:
  ClearErrors
  Exec $INSTDIR\uninst.exe

  done:
FunctionEnd

Section "encrypt" SEC01
  SectionIn RO
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "encrypt.exe"

  File "C:\extra\bin\libgpg-error-0.dll"
  File "C:\extra\bin\libgcrypt-11.dll"
  File "C:\MinGW\bin\libpthread-2.dll"
  File "C:\extra\bin\libcurl.dll"
  File "C:\extra\bin\libeay32.dll"
  File "C:\extra\bin\libidn-11.dll"
  File "C:\extra\bin\liblzma.dll"
  File "C:\extra\bin\librtmp.dll"
  File "C:\extra\bin\libssh2.dll"
  File "C:\extra\bin\libssl32.dll"
  File "C:\extra\bin\zlib1.dll"

  SetOutPath "$INSTDIR\docs"
  File "docs\README"
  Rename "README" "README.txt"
  File "docs\CHANGELOG"
  Rename "CHANGELOG" "CHANGELOG.txt"
  File "docs\COPYRIGHT"
  Rename "COPYRIGHT" "COPYRIGHT.txt"
  File "docs\GNU_GPLv3_LICENSE"
  Rename "GNU_GPLv3_LICENSE" "GNU_GPLv3_LICENSE.txt"
  File "docs\GNU_LGPLv3_LICENSE"
  Rename "GNU_LGPLv3_LICENSE" "GNU_LGPLv3_LICENSE.txt"
  File "docs\NewBSD_LICENSE"
  Rename "NewBSD_LICENSE" "NewBSD_LICENSE.txt"
  File "docs\MIT_LICENSE"
  Rename "MIT_LICENSE" "MIT_LICENSE.txt"
  File "docs\Apache_LICENSE"
  Rename "Apache_LICENSE" "Apache_LICENSE.txt"

  SetOutPath "$INSTDIR\pixmaps"
  File "pixmaps\encrypt.png"
  File "pixmaps\encrypt_button.png"

  SetOutPath "$INSTDIR\etc"
  ${If} ${RunningX64}
    File "etc\encrypt_w64.glade"
    Rename "encrypt_w64.glade" "encrypt_win.glade"
  ${Else}
    File "etc\encrypt_w32.glade"
    Rename "encrypt_w32.glade" "encrypt_win.glade"
  ${EndIf}  
  File "etc\encryptrc"

  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk" "$INSTDIR\encrypt.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk" "$INSTDIR\docs\LICENCE.txt"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk" "$INSTDIR\docs\README.txt"
SectionEnd

Section "GTK Runtime (v2.24.10)" SEC02
  SetOutPath $INSTDIR
    File "..\gtk2-runtime-2.24.10-2012-10-10-ash.exe"
    ExecWait "$INSTDIR\gtk2-runtime-2.24.10-2012-10-10-ash.exe"
  Delete "$INSTDIR\gtk2-runtime-2.24.10-2012-10-10-ash.exe"
SectionEnd

LangString DES01 ${LANG_ENGLISH} "$(^Name)"
LangString DES02 ${LANG_ENGLISH} "GTK2 runtime environment (version 2.24.10). Unless you know what you're doing, keep this checked."

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC01} $(DES01)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC02} $(DES02)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section -AdditionalIcons
  CreateShortCut "$SMPROGRAMS\encrypt\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\encrypt.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\encrypt.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCR "${EXPLORER_CONTEXT}" "" '$INSTDIR\encrypt.exe "%1"'
SectionEnd

Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "$(^Name) was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  Delete "$INSTDIR\encrypt.exe"

  Delete "$INSTDIR\libgcrypt-11.dll"
  Delete "$INSTDIR\libgpg-error-0.dll"
  Delete "$INSTDIR\libpthread-2.dll"
  Delete "$INSTDIR\libcurl.dll"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\libidn-11.dll"
  Delete "$INSTDIR\liblzma.dll"
  Delete "$INSTDIR\librtmp.dll"
  Delete "$INSTDIR\libssh2.dll"
  Delete "$INSTDIR\libssl32.dll"
  Delete "$INSTDIR\zlib1.dll"

  Delete "$INSTDIR\docs\README.txt"
  Delete "$INSTDIR\docs\CHANGELOG.txt"
  Delete "$INSTDIR\docs\COPYRIGHT.txt"
  Delete "$INSTDIR\docs\GNU_GPLv3_LICENSE.txt"
  Delete "$INSTDIR\docs\GNU_LGPLv3_LICENSE.txt"
  Delete "$INSTDIR\docs\NewBSD_LICENSE.txt"
  Delete "$INSTDIR\docs\MIT_LICENSE.txt"
  Delete "$INSTDIR\docs\Apache_LICENSE.txt"

  Delete "$INSTDIR\pixmaps\encrypt_button.png"
  Delete "$INSTDIR\pixmaps\encrypt.png"

  Delete "$INSTDIR\etc\encrypt_win.glade"
  Delete "$INSTDIR\etc\encryptrc"

  Delete "$INSTDIR\uninst.exe"

  Delete "$SMPROGRAMS\encrypt\Uninstall.lnk"
  Delete "$SMPROGRAMS\encrypt\ReadMe.lnk"
  Delete "$SMPROGRAMS\encrypt\Licence.lnk"
  Delete "$SMPROGRAMS\encrypt\encrypt.lnk"

  RMDir "$SMPROGRAMS\encrypt"
  RMDir "$INSTDIR\docs"
  RMDIR "$INSTDIR\pixmaps"
  RMDIR "$INSTDIR\etc"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKCR "${EXPLORER_CONTEXT}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose false
SectionEnd
