#!/bin/sh

install_name_tool -id @executable_path/../Frameworks/libgcrypt.20.dylib         ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
install_name_tool -id @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -id @executable_path/../Frameworks/liblzma.5.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/liblzma.5.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextlib-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.5.dylib
install_name_tool -id @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libasprintf.0.dylib
install_name_tool -id @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libintl.8.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextsrc-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.5.dylib
install_name_tool -id @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libtextstyle.0.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib

install_name_tool -change /opt/local/lib/libgcrypt.20.dylib         @executable_path/../Frameworks/libgcrypt.20.dylib         ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgpg-error.0.dylib       @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgpg-error.0.dylib       @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
install_name_tool -change /opt/local/lib/liblzma.5.dylib            @executable_path/../Frameworks/liblzma.5.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgettextlib-0.22.5.dylib @executable_path/../Frameworks/libgettextlib-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libasprintf.0.dylib        @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgettextsrc-0.22.5.dylib @executable_path/../Frameworks/libgettextsrc-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libtextstyle.0.dylib       @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgettextpo.0.dylib       @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /opt/local/lib/libgettextlib-0.22.5.dylib @executable_path/../Frameworks/libgettextlib-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libasprintf.0.dylib        @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libgettextsrc-0.22.5.dylib @executable_path/../Frameworks/libgettextsrc-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libtextstyle.0.dylib       @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libgettextpo.0.dylib       @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /opt/local/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.5.dylib
install_name_tool -change /opt/local/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib
install_name_tool -change /opt/local/lib/libgettextlib-0.22.5.dylib @executable_path/../Frameworks/libgettextlib-0.22.5.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.5.dylib
install_name_tool -change /opt/local/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.5.dylib
install_name_tool -change /opt/local/lib/libtextstyle.0.dylib       @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.5.dylib

chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/liblzma.5.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.5.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libasprintf.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libintl.8.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.5.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libtextstyle.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib
