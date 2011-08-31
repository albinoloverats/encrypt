!define PRODUCT_NAME "encrypt"
!define PRODUCT_VERSION "2011.09"
!define PRODUCT_PUBLISHER "albinoloverats ~ Software Development"
!define PRODUCT_WEB_SITE "https://albinoloverats.net/projects/encrypt"
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
  File "encrypt_win32.glade"
  File "C:\Program Files\GTK2-Runtime\bin\freetype6.dll"
  File "C:\Program Files\GTK2-Runtime\bin\intl.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libatk-1.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libcairo-2.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libexpat-1.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libfontconfig-1.dll"
  File "C:\MinGW\bin\libgcrypt-11.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgdk-win32-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgdk_pixbuf-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgio-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libglib-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgmodule-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgobject-2.0-0.dll"
  File "C:\MinGW\bin\libgpg-error-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgthread-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libgtk-win32-2.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libpango-1.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libpangocairo-1.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libpangoft2-1.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libpangowin32-1.0-0.dll"
  File "C:\Program Files\GTK2-Runtime\bin\libpng14-14.dll"
  File "C:\MinGW\bin\libpthread-2.dll"
  File "C:\Program Files\GTK2-Runtime\bin\zlib1.dll"
  SetOutPath "$INSTDIR\docs"
  File "doc\Licence.txt"
  File "doc\ReadMe.txt"
  File "doc\GNU_LGPGv3_License.txt"
  File "doc\FreeBSD_License.txt"
  SetOutPath "$INSTDIR\pixmaps"
  File "pixmaps\encrypt.svg"
  File "pixmaps\encrypt.png"
  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk" "$INSTDIR\encrypt.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk" "$INSTDIR\docs\Licence.txt"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk" "$INSTDIR\docs\ReadMe.txt"
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
  Delete "$INSTDIR\encrypt.exe"
  Delete "$INSTDIR\encrypt_win32.glade"
  Delete "$INSTDIR\freetype6.dll"
  Delete "$INSTDIR\intl.dll"
  Delete "$INSTDIR\libatk-1.0-0.dll"
  Delete "$INSTDIR\libcairo-2.dll"
  Delete "$INSTDIR\libexpat-1.dll"
  Delete "$INSTDIR\libfontconfig-1.dll"
  Delete "$INSTDIR\libgcrypt-11.dll"
  Delete "$INSTDIR\libgdk-win32-2.0-0.dll"
  Delete "$INSTDIR\libgdk_pixbuf-2.0-0.dll"
  Delete "$INSTDIR\libgio-2.0-0.dll"
  Delete "$INSTDIR\libglib-2.0-0.dll"
  Delete "$INSTDIR\libgmodule-2.0-0.dll"
  Delete "$INSTDIR\libgobject-2.0-0.dll"
  Delete "$INSTDIR\libgpg-error-0.dll"
  Delete "$INSTDIR\libgthread-2.0-0.dll"
  Delete "$INSTDIR\libgtk-win32-2.0-0.dll"
  Delete "$INSTDIR\libpango-1.0-0.dll"
  Delete "$INSTDIR\libpangocairo-1.0-0.dll"
  Delete "$INSTDIR\libpangoft2-1.0-0.dll"
  Delete "$INSTDIR\libpangowin32-1.0-0.dll"
  Delete "$INSTDIR\libpng14-14.dll"
  Delete "$INSTDIR\libpthread-2.dll"
  Delete "$INSTDIR\zlib1.dll"
  Delete "$INSTDIR\docs\Licence.txt"
  Delete "$INSTDIR\docs\ReadMe.txt"
  Delete "$INSTDIR\docs\GNU_LGPGv3_License.txt"
  Delete "$INSTDIR\docs\FreeBSD_License.txt"
  Delete "$INSTDIR\pixmaps\encrypt.svg"
  Delete "$INSTDIR\pixmaps\encrypt.png"
  Delete "$SMPROGRAMS\encrypt\Uninstall.lnk"
  Delete "$SMPROGRAMS\encrypt\ReadMe.lnk"
  Delete "$SMPROGRAMS\encrypt\Licence.lnk"
  Delete "$SMPROGRAMS\encrypt\encrypt.lnk"

  RMDir "$SMPROGRAMS\encrypt"
  RMDir "$INSTDIR\docs"
  RMDIR "$INSTDIR\pixmaps"
  RMDir "$INSTDIR"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose false
SectionEnd
