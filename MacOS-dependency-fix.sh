#!/bin/sh

install_name_tool -id @executable_path/../Frameworks/libgcrypt.20.dylib         ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
install_name_tool -id @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -id @executable_path/../Frameworks/liblzma.5.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/liblzma.5.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextlib-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.4.dylib
install_name_tool -id @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libasprintf.0.dylib
install_name_tool -id @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libintl.8.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextsrc-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.4.dylib
install_name_tool -id @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libtextstyle.0.dylib
install_name_tool -id @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib

install_name_tool -change /usr/local/opt/libgcrypt/lib/libgcrypt.20.dylib                 @executable_path/../Frameworks/libgcrypt.20.dylib         ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/libgpg-error/lib/libgpg-error.0.dylib            @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/libgpg-error/lib/libgpg-error.0.dylib            @executable_path/../Frameworks/libgpg-error.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
install_name_tool -change /usr/local/opt/xz/lib/liblzma.5.dylib                           @executable_path/../Frameworks/liblzma.5.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libgettextlib-0.22.4.dylib           @executable_path/../Frameworks/libgettextlib-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libasprintf.0.dylib                  @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libintl.8.dylib                      @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libgettextsrc-0.22.4.dylib           @executable_path/../Frameworks/libgettextsrc-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libtextstyle.0.dylib                 @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libgettextpo.0.dylib                 @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/MacOS/Encrypt
install_name_tool -change /usr/local/opt/gettext/lib/libgettextlib-0.22.4.dylib           @executable_path/../Frameworks/libgettextlib-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/opt/gettext/lib/libasprintf.0.dylib                  @executable_path/../Frameworks/libasprintf.0.dylib        ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/opt/gettext/lib/libintl.8.dylib                      @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/opt/gettext/lib/libgettextsrc-0.22.4.dylib           @executable_path/../Frameworks/libgettextsrc-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/opt/gettext/lib/libtextstyle.0.dylib                 @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/opt/gettext/lib/libgettextpo.0.dylib                 @executable_path/../Frameworks/libgettextpo.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
install_name_tool -change /usr/local/Cellar/gettext/0.22.4/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.4.dylib
install_name_tool -change /usr/local/Cellar/gettext/0.22.4/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib
install_name_tool -change /usr/local/Cellar/gettext/0.22.4/lib/libgettextlib-0.22.4.dylib @executable_path/../Frameworks/libgettextlib-0.22.4.dylib ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.4.dylib
install_name_tool -change /usr/local/Cellar/gettext/0.22.4/lib/libintl.8.dylib            @executable_path/../Frameworks/libintl.8.dylib            ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.4.dylib
install_name_tool -change /usr/local/Cellar/gettext/0.22.4/lib/libtextstyle.0.dylib       @executable_path/../Frameworks/libtextstyle.0.dylib       ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.4.dylib

chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgcrypt.20.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgpg-error.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/liblzma.5.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextlib-0.22.4.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libasprintf.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libintl.8.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextsrc-0.22.4.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libtextstyle.0.dylib
chmod 755 ${BUILT_PRODUCTS_DIR}/Encrypt.app/Contents/Frameworks/libgettextpo.0.dylib
