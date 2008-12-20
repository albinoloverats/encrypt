!define PRODUCT_NAME "encrypt"
!define PRODUCT_VERSION "TBA"
!define PRODUCT_PUBLISHER "albinoloverats ~ Software Development"
!define PRODUCT_WEB_SITE "https://albinoloverats.net/encrypt"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\encrypt.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

ShowInstDetails show
ShowUnInstDetails show
SetCompressor lzma


Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${PRODUCT_NAME}-${PRODUCT_VERSION}-install.exe"
LoadLanguageFile "${NSISDIR}\Contrib\Language files\English.nlf"
InstallDir "$PROGRAMFILES\${PRODUCT_NAME}"
Icon "${NSISDIR}\Contrib\Graphics\Icons\classic-install.ico"
UninstallIcon "${NSISDIR}\Contrib\Graphics\Icons\classic-uninstall.ico"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
LicenseText "If you accept all the terms of the agreement, choose I Agree to continue. You must accept the agreement to install $(^Name)."
LicenseData "doc\Licence.txt"
ShowInstDetails show
ShowUnInstDetails show

Section "main" SEC01
  SetOutPath "$INSTDIR"
  SetOverwrite on
  File "encrypt.exe"
  SetOutPath "$INSTDIR\doc"
  File "doc\Licence.txt"
  File "doc\ReadMe.txt"
  SetOutPath "$INSTDIR\lib"
  File "lib\xtea.dll"
  File "lib\anubis.dll"
  File "lib\serpent.dll"
  SetOutPath "$INSTDIR\src"
  File "..\encrypt.tar.bz2"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk" "$INSTDIR\encrypt.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk" "$INSTDIR\doc\Licence.txt"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk" "$INSTDIR\doc\ReadMe.txt"
SectionEnd

Section -AdditionalIcons
  CreateShortCut "$SMPROGRAMS\encrypt\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\encrypt.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\encrypt.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
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
  Delete "$INSTDIR\uninst.exe"
  Delete "$INSTDIR\lib\xtea.dll"
  Delete "$INSTDIR\lib\anubis.dll"
  Delete "$INSTDIR\lib\serpent.dll"
  Delete "$INSTDIR\doc\ReadMe.txt"
  Delete "$INSTDIR\doc\Licence.txt"
  Delete "$INSTDIR\src\encrypt.tar.bz2"
  Delete "$INSTDIR\encrypt.exe"

  Delete "$SMPROGRAMS\encrypt\Uninstall.lnk"
  Delete "$SMPROGRAMS\encrypt\ReadMe.lnk"
  Delete "$SMPROGRAMS\encrypt\Licence.lnk"
  Delete "$SMPROGRAMS\encrypt\encrypt.lnk"

  RMDir "$SMPROGRAMS\encrypt"
  RMDir "$INSTDIR\lib"
  RMDir "$INSTDIR\doc"
  RMDir "$INSTDIR\src"
  RMDir "$INSTDIR"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose false
SectionEnd
