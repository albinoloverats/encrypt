!include "MUI.nsh"
!include x64.nsh

!define MUI_ABORTWARNING
!define MUI_ICON   "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!define PRODUCT_NAME       "encrypt"
!define PRODUCT_VERSION    "2021.10"
!define PRODUCT_PUBLISHER  "albinoloverats ~ Software Development"
!define PRODUCT_WEB_SITE   "https://albinoloverats.net/projects/encrypt"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\encrypt.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define EXPLORER_CONTEXT   "*\shell\Encrypt/Decrypt"
!define EXPLORER_COMMAND   "command"

SetCompressor     lzma
Name              "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile           "${PRODUCT_NAME}-${PRODUCT_VERSION}-install.exe"
InstallDir        "$PROGRAMFILES\${PRODUCT_NAME}"
InstallDirRegKey  HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails   show
ShowUnInstDetails show

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "docs\LICENCE"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "British"
!insertmacro MUI_RESERVEFILE_INSTALLOPTIONS

VIProductVersion "${PRODUCT_VERSION}.0.0"
VIAddVersionKey /LANG=${LANG_BRITISH} "ProductName"      "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_BRITISH} "Comments"         "encrypt is a simple, cross platform utility for securing your personal files"
VIAddVersionKey /LANG=${LANG_BRITISH} "CompanyName"      "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "LegalCopyright"   "Copyright (c) 2004-2021, ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "FileDescription"  "Installer for ${PRODUCT_NAME} version ${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "FileVersion"      "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "ProductVersion"   "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=${LANG_BRITISH} "InternalName"     "${PRODUCT_NAME}"
VIAddVersionKey /LANG=${LANG_BRITISH} "LegalTrademarks"  "Copyright (c) 2004-2021, ${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=${LANG_BRITISH} "OriginalFilename" "${PRODUCT_NAME}-${PRODUCT_VERSION}-install.exe"

Function .onInit
	${If} ${RunningX64}
		StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCT_NAME}"
	${Else}
		MessageBox MB_OK|MB_ICONEXCLAMATION \
			"${PRODUCT_NAME} is now 64-bit and, as such, will not install of 32-bit versions of Windows."
		Abort
	${EndIf}

	ReadRegStr $R0 HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"
	StrCmp $R0 "" done

	FindProcDLL::FindProc "${PRODUCT_NAME}.exe"
	IntCmp $R0 1 0 notRunning
		MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
			"${PRODUCT_NAME} is currently running. $\n$\nClick `OK` to continue or `Cancel` to cancel this upgrade." \
			IDOK stopRunning
		Abort
	stopRunning:
		KillProcDLL::KillProc "${PRODUCT_NAME}.exe"
	notRunning:

	MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
		"${PRODUCT_NAME} is already installed. $\n$\nClick `OK` to remove the previous version or `Cancel` to cancel this upgrade." \
		IDOK uninst
	Abort

	uninst:
	ClearErrors
	Exec $INSTDIR\uninst.exe

	done:
FunctionEnd

Section -encrypt
	SetOutPath "$INSTDIR"
	SetOverwrite on
	File "encrypt.exe"

	File "C:\msys64\mingw64\bin\libwinpthread-1.dll"
	File "C:\msys64\mingw64\bin\libcurl-4.dll"
	File "C:\msys64\mingw64\bin\libbrotlidec.dll"
	File "C:\msys64\mingw64\bin\libbrotlicommon.dll"
	File "C:\msys64\mingw64\bin\libidn2-0.dll"
	File "C:\msys64\mingw64\bin\libintl-8.dll"
	File "C:\msys64\mingw64\bin\libiconv-2.dll"
	File "C:\msys64\mingw64\bin\libunistring-2.dll"
	File "C:\msys64\mingw64\bin\libnghttp2-14.dll"
	File "C:\msys64\mingw64\bin\libcrypto-1_1-x64.dll"
	File "C:\msys64\mingw64\bin\libssl-1_1-x64.dll"
	File "C:\msys64\mingw64\bin\libpsl-5.dll"
	File "C:\msys64\mingw64\bin\libthai-0.dll"
	File "C:\msys64\mingw64\bin\libdatrie-1.dll"
	File "C:\msys64\mingw64\bin\zlib1.dll"
	File "C:\msys64\mingw64\bin\libgcrypt-20.dll"
	File "C:\msys64\mingw64\bin\libgpg-error-0.dll"
	File "C:\msys64\mingw64\bin\libglib-2.0-0.dll"
	File "C:\msys64\mingw64\bin\libpcre-1.dll"
	File "C:\msys64\mingw64\bin\libgobject-2.0-0.dll"
	File "C:\msys64\mingw64\bin\libffi-7.dll"
	File "C:\msys64\mingw64\bin\libgtk-3-0.dll"
	File "C:\msys64\mingw64\bin\libgdk-3-0.dll"
	File "C:\msys64\mingw64\bin\libatk-1.0-0.dll"
	File "C:\msys64\mingw64\bin\libcairo-gobject-2.dll"
	File "C:\msys64\mingw64\bin\libcairo-2.dll"
	File "C:\msys64\mingw64\bin\libgcc_s_seh-1.dll"
	File "C:\msys64\mingw64\bin\libfontconfig-1.dll"
	File "C:\msys64\mingw64\bin\libexpat-1.dll"
	File "C:\msys64\mingw64\bin\libfreetype-6.dll"
	File "C:\msys64\mingw64\bin\libbz2-1.dll"
	File "C:\msys64\mingw64\bin\libharfbuzz-0.dll"
	File "C:\msys64\mingw64\bin\libgraphite2.dll"
	File "C:\msys64\mingw64\bin\libstdc++-6.dll"
	File "C:\msys64\mingw64\bin\libpixman-1-0.dll"
	File "C:\msys64\mingw64\bin\libpng16-16.dll"
	File "C:\msys64\mingw64\bin\libepoxy-0.dll"
	File "C:\msys64\mingw64\bin\libgdk_pixbuf-2.0-0.dll"
	File "C:\msys64\mingw64\bin\libgio-2.0-0.dll"
	File "C:\msys64\mingw64\bin\libgmodule-2.0-0.dll"
	File "C:\msys64\mingw64\bin\libpango-1.0-0.dll"
	File "C:\msys64\mingw64\bin\libfribidi-0.dll"
	File "C:\msys64\mingw64\bin\libpangocairo-1.0-0.dll"
	File "C:\msys64\mingw64\bin\libpangoft2-1.0-0.dll"
	File "C:\msys64\mingw64\bin\libpangowin32-1.0-0.dll"
	File "C:\msys64\mingw64\bin\liblzma-5.dll"
	File "C:\msys64\mingw64\bin\libssh2-1.dll"
	File "C:\msys64\mingw64\bin\libzstd.dll"

	SetOutPath "$INSTDIR\lib"
	File /r "C:\msys64\mingw64\lib\gdk-pixbuf-2.0"

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
	File "pixmaps\encrypt_key.png"

	SetOutPath "$INSTDIR\etc"
	File "etc\encrypt_win.glade"
	File "etc\encryptrc"

	SetOutPath "$INSTDIR\share\glib-2.0\schemas"
	File "C:\msys64\mingw64\share\glib-2.0\schemas\gschemas.compiled"

	SetOutPath "$INSTDIR\share\icons"
	File /r "C:\msys64\mingw64\share\icons\Adwaita"
	File /r "C:\msys64\mingw64\share\icons\hicolor"

	SetOutPath "$INSTDIR"
	CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
	CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk" "$INSTDIR\encrypt.exe"
	CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk" "$INSTDIR\docs\LICENCE.txt"
	CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk" "$INSTDIR\docs\README.txt"
SectionEnd

Section -AdditionalIcons
	CreateShortCut "$SMPROGRAMS\encrypt\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
	WriteUninstaller "$INSTDIR\uninst.exe"
	WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" ""                 "$INSTDIR\encrypt.exe"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName"      "$(^Name)"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString"  "$INSTDIR\uninst.exe"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon"      "$INSTDIR\encrypt.exe"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion"   "${PRODUCT_VERSION}"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout"     "${PRODUCT_WEB_SITE}"
	WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher"        "${PRODUCT_PUBLISHER}"
	WriteRegStr HKCR "${EXPLORER_CONTEXT}\${EXPLORER_COMMAND}" "" '$INSTDIR\encrypt.exe "%1"'
SectionEnd

Function un.onInit
	MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove $(^Name) and all of its components?" IDYES +2
	Abort
FunctionEnd

Section Uninstall
	Delete "$INSTDIR\encrypt.exe"

	Delete "$INSTDIR\libwinpthread-1.dll"
	Delete "$INSTDIR\libcurl-4.dll"
	Delete "$INSTDIR\libbrotlidec.dll"
	Delete "$INSTDIR\libbrotlicommon.dll"
	Delete "$INSTDIR\libidn2-0.dll"
	Delete "$INSTDIR\libintl-8.dll"
	Delete "$INSTDIR\libiconv-2.dll"
	Delete "$INSTDIR\libunistring-2.dll"
	Delete "$INSTDIR\libnghttp2-14.dll"
	Delete "$INSTDIR\libcrypto-1_1-x64.dll"
	Delete "$INSTDIR\libssl-1_1-x64.dll"
	Delete "$INSTDIR\libpsl-5.dll"
	Delete "$INSTDIR\libthai-0.dll"
	Delete "$INSTDIR\libdatrie-1.dll"
	Delete "$INSTDIR\zlib1.dll"
	Delete "$INSTDIR\libgcrypt-20.dll"
	Delete "$INSTDIR\libgpg-error-0.dll"
	Delete "$INSTDIR\libglib-2.0-0.dll"
	Delete "$INSTDIR\libpcre-1.dll"
	Delete "$INSTDIR\libgobject-2.0-0.dll"
	Delete "$INSTDIR\libffi-7.dll"
	Delete "$INSTDIR\libgtk-3-0.dll"
	Delete "$INSTDIR\libgdk-3-0.dll"
	Delete "$INSTDIR\libatk-1.0-0.dll"
	Delete "$INSTDIR\libcairo-gobject-2.dll"
	Delete "$INSTDIR\libcairo-2.dll"
	Delete "$INSTDIR\libgcc_s_seh-1.dll"
	Delete "$INSTDIR\libfontconfig-1.dll"
	Delete "$INSTDIR\libexpat-1.dll"
	Delete "$INSTDIR\libfreetype-6.dll"
	Delete "$INSTDIR\libbz2-1.dll"
	Delete "$INSTDIR\libharfbuzz-0.dll"
	Delete "$INSTDIR\libgraphite2.dll"
	Delete "$INSTDIR\libstdc++-6.dll"
	Delete "$INSTDIR\libpixman-1-0.dll"
	Delete "$INSTDIR\libpng16-16.dll"
	Delete "$INSTDIR\libepoxy-0.dll"
	Delete "$INSTDIR\libgdk_pixbuf-2.0-0.dll"
	Delete "$INSTDIR\libgio-2.0-0.dll"
	Delete "$INSTDIR\libgmodule-2.0-0.dll"
	Delete "$INSTDIR\libpango-1.0-0.dll"
	Delete "$INSTDIR\libfribidi-0.dll"
	Delete "$INSTDIR\libpangocairo-1.0-0.dll"
	Delete "$INSTDIR\libpangoft2-1.0-0.dll"
	Delete "$INSTDIR\libpangowin32-1.0-0.dll"
	Delete "$INSTDIR\liblzma-5.dll"
	Delete "$INSTDIR\libssh2-1.dll"
	Delete "$INSTDIR\libzstd.dll"

	Delete "$INSTDIR\docs\README.txt"
	Delete "$INSTDIR\docs\CHANGELOG.txt"
	Delete "$INSTDIR\docs\COPYRIGHT.txt"
	Delete "$INSTDIR\docs\GNU_GPLv3_LICENSE.txt"
	Delete "$INSTDIR\docs\GNU_LGPLv3_LICENSE.txt"
	Delete "$INSTDIR\docs\NewBSD_LICENSE.txt"
	Delete "$INSTDIR\docs\MIT_LICENSE.txt"
	Delete "$INSTDIR\docs\Apache_LICENSE.txt"

	Delete "$INSTDIR\pixmaps\encrypt_key.png"
	Delete "$INSTDIR\pixmaps\encrypt_button.png"
	Delete "$INSTDIR\pixmaps\encrypt.png"

	Delete "$INSTDIR\etc\encrypt_win.glade"
	Delete "$INSTDIR\etc\encryptrc"

	Delete "$INSTDIR\share\glib-2.0\schemas\gschemas.compiled"
	RMDir "$INSTDIR\share\glib-2.0\schemas"
	RMDir "$INSTDIR\share\glib-2.0"

	RMDir /r "$INSTDIR\lib"

	RMDir /r "$INSTDIR\share\icons\Adwaita"
	RMDir /r "$INSTDIR\share\icons\hicolor"
	RMDir "$INSTDIR\share\icons"

	Delete "$INSTDIR\uninst.exe"

	Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
	Delete "$SMPROGRAMS\${PRODUCT_NAME}\ReadMe.lnk"
	Delete "$SMPROGRAMS\${PRODUCT_NAME}\Licence.lnk"
	Delete "$SMPROGRAMS\${PRODUCT_NAME}\encrypt.lnk"

	RMDir "$SMPROGRAMS\encrypt"

	RMDir "$INSTDIR\docs"
	RMDIR "$INSTDIR\pixmaps"
	RMDIR "$INSTDIR\etc"
	RMDir "$INSTDIR\share"
	RMDir "$INSTDIR"

	DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
	DeleteRegKey HKCR "${EXPLORER_CONTEXT}"
	DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
	SetAutoClose false
SectionEnd
