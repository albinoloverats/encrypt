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
!define EXPLORER_CONTEXT "*\shell\Encrypt/Decrypt"
!define EXPLORER_COMMAND "command"

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
!insertmacro MUI_LANGUAGE "British"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

VIProductVersion "${PRODUCT_VERSION}.0.0"
VIAddVersionKey /LANG=${LANG_BRITISH} "ProductName"      "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_BRITISH} "Comments"         "encrypt is a simple, cross platform utility for securing your personal files"
VIAddVersionKey /LANG=${LANG_BRITISH} "CompanyName"      "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "LegalCopyright"   "Copyright (c) 2004-2014, ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "FileDescription"  "Installer for ${PRODUCT_NAME} version ${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "FileVersion"      "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "ProductVersion"   "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "InternalName"     "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_BRITISH} "LegalTrademarks"  "Copyright (c) 2004-2014, ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "OriginalFilename" "${PRODUCT_NAME}-${PRODUCT_VERSION}-install.exe"

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

  File "C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\libgcc_s_dw2-1.dll"
  File "C:\Program Files (x86)\Dev-Cpp\MinGW64\bin\libgcc_s_sjlj-1.dll"

  File "C:\extra\curl-7.34.0-devel-mingw32\bin\libcurl.dll"
  File "C:\extra\curl-7.34.0-devel-mingw32\bin\libeay32.dll"
  File "C:\extra\curl-7.34.0-devel-mingw32\bin\libidn-11.dll"
  File "C:\extra\curl-7.34.0-devel-mingw32\bin\ssleay32.dll"
  File "C:\extra\curl-7.34.0-devel-mingw32\bin\zlib1.dll"

  File "C:\extra\libgcrypt-1.6.1-2\bin\libgcrypt-20.dll"
  File "C:\extra\libgpg-error-1.13-1\bin\libgpg-error-0.dll"
  File "C:\extra\pthreads-w32-2-9-1\dll\x86\pthreadGC2.dll"
  File "C:\extra\xz-5.0.5-windows\bin_i486\liblzma.dll"

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

Section "GTK+3 Runtime" SEC02
  SetOutPath $INSTDIR
    File "..\encrypt_extras\GTK+-Runtime-3.6.1_(TARNYKO).exe"
    ExecWait "$INSTDIR\GTK+-Runtime-3.6.1_(TARNYKO).exe"
  Delete "$INSTDIR\GTK+-Runtime-3.6.1_(TARNYKO).exe"
SectionEnd

Section "User Guide" SEC03
  SetOverwrite on

  SetOutPath "$INSTDIR\docs\User Guide"
  File "..\encrypt_extras\mark_condic\User Guide\index.html"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt_button.png"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt1.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt2.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt3.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt4.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt5.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt6.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt7.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt8b.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt9b.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt10.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt11.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt12.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt14.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt15.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt16.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt17.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt18.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt19.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt20.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt21.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt22.jpg"
  File "..\encrypt_extras\mark_condic\User Guide\encrypt22b.jpg"

  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\User Guide.lnk" "$INSTDIR\docs\User Guide\index.html"
SectionEnd

LangString DES01 ${LANG_ENGLISH} "$(^Name)"
LangString DES02 ${LANG_ENGLISH} "GTK+3 Runtime Environment (it's recommended you install this unless you know what you're doing)"
LangString DES03 ${LANG_ENGLISH} "encrypt User Guide (kindly provided by Mark Condic)"

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC01} $(DES01)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC02} $(DES02)
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC03} $(DES03)
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
  WriteRegStr HKCR "${EXPLORER_CONTEXT}\${EXPLORER_COMMAND}" "" '$INSTDIR\encrypt.exe "%1"'
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

  Delete "$INSTDIR\libgcc_s_dw2-1.dll"

  Delete "$INSTDIR\libcurl.dll"
  Delete "$INSTDIR\libeay32.dll"
  Delete "$INSTDIR\libidn-11.dll"
  Delete "$INSTDIR\ssleay32.dll"
  Delete "$INSTDIR\zlib1.dll"

  Delete "$INSTDIR\libgcrypt-11.dll"
  Delete "$INSTDIR\libgpg-error-0.dll"
  Delete "$INSTDIR\pthreadGC2.dll"
  Delete "$INSTDIR\liblzma.dll"

  Delete "$INSTDIR\docs\README.txt"
  Delete "$INSTDIR\docs\CHANGELOG.txt"
  Delete "$INSTDIR\docs\COPYRIGHT.txt"
  Delete "$INSTDIR\docs\GNU_GPLv3_LICENSE.txt"
  Delete "$INSTDIR\docs\GNU_LGPLv3_LICENSE.txt"
  Delete "$INSTDIR\docs\NewBSD_LICENSE.txt"
  Delete "$INSTDIR\docs\MIT_LICENSE.txt"
  Delete "$INSTDIR\docs\Apache_LICENSE.txt"

  Delete "$INSTDIR\docs\User Guide\index.html"
  Delete "$INSTDIR\docs\User Guide\encrypt_button.png"
  Delete "$INSTDIR\docs\User Guide\encrypt1.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt2.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt3.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt4.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt5.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt6.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt7.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt8b.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt9b.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt10.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt11.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt12.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt14.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt15.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt16.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt17.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt18.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt19.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt20.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt21.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt22.jpg"
  Delete "$INSTDIR\docs\User Guide\encrypt22b.jpg"

  Delete "$INSTDIR\pixmaps\encrypt_button.png"
  Delete "$INSTDIR\pixmaps\encrypt.png"

  Delete "$INSTDIR\etc\encrypt_win.glade"
  Delete "$INSTDIR\etc\encryptrc"

  Delete "$INSTDIR\GTK+-Runtime-3.6.1_(TARNYKO).exe"

  Delete "$INSTDIR\uninst.exe"

  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\User Guide.lnk"

  RMDir "$SMPROGRAMS\encrypt"
  RMDir "$INSTDIR\docs\User Guide"
  RMDir "$INSTDIR\docs"
  RMDIR "$INSTDIR\pixmaps"
  RMDIR "$INSTDIR\etc"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKCR "${EXPLORER_CONTEXT}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose false
SectionEnd
