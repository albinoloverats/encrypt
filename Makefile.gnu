.PHONY: clean distclean

APP      = encrypt
ALT      = decrypt

SOURCE   = src/main.c src/init.c src/crypt.c src/encrypt.c src/decrypt.c src/crypt_io.c
GUI      = src/gui-gtk.c
COMMON   = src/common/error.c src/common/ccrypt.c src/common/tlv.c src/common/version.c src/common/fs.c src/common/cli.c src/common/dir.c src/common/ecc.c src/common/non-gnu.c

CLI_CFLAGS   = ${CFLAGS} -Wall -Wextra -std=gnu99 $(shell libgcrypt-config --cflags) -pipe -O2 -Wrestrict -Wformat=2 -Wno-unused-result
CLI_CPPFLAGS = -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DGCRYPT_NO_DEPRECATED -DGIT_COMMIT=\"$(shell git log | head -n1 | cut -f2 -d' ')\" -DBUILD_OS=\"$(shell grep PRETTY_NAME /etc/os-release | cut -d= -f2)\"
GUI_CFLAGS   = ${CLI_CFLAGS} $(shell pkg-config --cflags gtk+-3.0 gmodule-2.0)
GUI_CPPFLAGS = ${CLI_CPPFLAGS} -DBUILD_GUI
DEBUG_WO     = -O0 -ggdb -pg -D__DEBUG__ -D__DEBUG_GUI__ -DMALLOC_CHECK_=1
DEBUG_WE     = ${DEBUG_WO} -D__DEBUG_WITH_ENCRYPTION__
CLI_LIBS     = $(shell libgcrypt-config --libs) -lpthread -lcurl -llzma
GUI_LIBS     = ${CLI_LIBS} $(shell pkg-config --libs gtk+-3.0 gmodule-2.0)

ALL_CLI          = -DALL_CFLAGS=\""$(shell echo ${CLI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${CLI_CPPFLAGS}             | tr "\"" "'" )"\"
ALL_CLI_DEBUG_WO = -DALL_CFLAGS=\""$(shell echo ${CLI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${CLI_CPPFLAGS} ${DEBUG_WO} | tr "\"" "'" )"\"
ALL_CLI_DEBUG_WE = -DALL_CFLAGS=\""$(shell echo ${CLI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${CLI_CPPFLAGS} ${DEBUG_WE} | tr "\"" "'" )"\"
ALL_GUI          = -DALL_CFLAGS=\""$(shell echo ${GUI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${GUI_CPPFLAGS}             | tr "\"" "'" )"\"
ALL_GUI_DEBUG_WO = -DALL_CFLAGS=\""$(shell echo ${GUI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${GUI_CPPFLAGS} ${DEBUG_WO} | tr "\"" "'" )"\"
ALL_GUI_DEBUG_WE = -DALL_CFLAGS=\""$(shell echo ${GUI_CFLAGS})"\" -DALL_CPPFLAGS=\""$(shell echo ${GUI_CPPFLAGS} ${DEBUG_WO} | tr "\"" "'" )"\"

all: gui language man

debug: cli-debug

cli: symlink-decrypt
	 @${CC} ${CLI_LIBS} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_CLI}                             -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

cli-debug: symlink-decrypt
	 @${CC} ${CLI_LIBS} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_CLI_DEBUG_WO}        ${DEBUG_WO} -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

cli-debug-with-encryption: symlink-decrypt
	 @${CC} ${CLI_LIBS} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_CLI_DEBUG_WE}        ${DEBUG_WO} -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui: symlink-decrypt
	 @${CC} ${GUI_LIBS} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_GUI}          ${GUI}             -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} ${GUI} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui-debug: symlink-decrypt
	 @${CC} ${GUI_LIBS} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_GUI_DEBUG_WO} ${GUI} ${DEBUG_WO} -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} ${GUI} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui-debug-with-encryption: symlink-decrypt
	 @${CC} ${GUI_LIBS} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${SOURCE} ${COMMON} ${ALL_GUI_DEBUG_WE} ${GUI} ${DEBUG_WO} -o ${APP}
	-@echo -e "built ‘`echo -e ${SOURCE} ${COMMON} ${GUI} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

symlink-decrypt:
	 @ln -fs ${APP} ${ALT}
	-@echo -e "linked ‘${ALT}’ → ‘${APP}’"

language:
	-@echo -e "TODO - string translation"
#	@${MAKE} -C po

man:
	 @gzip -c docs/${APP}.1a > ${APP}.1a.gz
	-@echo -e "compressing ‘docs/${APP}.1a’ → ‘${APP}.1a.gz"

install:
# install the main executable, also link decrypt
	 @install -m 755 -s -D -T ${APP} ${PREFIX}/usr/bin/${APP}
	-@echo -e "installed ‘${APP}’ → ‘${PREFIX}/usr/bin/${APP}’"
	 @ln -f ${PREFIX}/usr/bin/${APP} ${PREFIX}/usr/bin/${ALT}
	-@echo -e "linked ‘${ALT}’ → ‘${APP}’"
# install the pixmaps
	 @install -m 644 -D -T pixmaps/encrypt.svg ${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt.svg
	-@echo -e "installed ‘pixmaps/encrypt.svg’ → ‘${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt.svg’"
	 @install -m 644 -D -T pixmaps/encrypt_button.svg ${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg
	-@echo -e "installed ‘pixmaps/encrypt_button.svg’ → ‘${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg’"
# next encrypt.glade
	 @install -m 644 -D -T etc/encrypt.glade ${PREFIX}/usr/${LOCAL}/share/encrypt/encrypt.glade
	-@echo -e "installed ‘etc/encrypt.glade’ → ‘${PREFIX}/usr/${LOCAL}/share/encrypt/encrypt.glade’"
# and an example rc file
	 @install -m 644 -D -T etc/encryptrc ${PREFIX}/usr/${LOCAL}/share/encrypt/encryptrc
	-@echo -e "installed ‘etc/encryptrc’ → ‘${PREFIX}/usr/${LOCAL}/share/encrypt/encryptrc’"
# ditto, but this time for the man page
	 @install -m 644 -D -T encrypt.1a.gz ${PREFIX}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz
	-@echo -e "installed ‘encrypt.1a.gz’ → ‘${PREFIX}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz’"
# and then the desktop files
	 @install -m 644 -D -T etc/encrypt.desktop ${PREFIX}/usr/${LOCAL}/share/applications/encrypt.desktop
	-@echo -e "installed ‘etc/encrypt.desktop’ → ‘${PREFIX}/usr/${LOCAL}/share/applications/encrypt.desktop’"
	 @install -m 644 -D -T etc/thunar-sendto.desktop ${PREFIX}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop
	-@echo -e "installed ‘etc/thunar-sendto.desktop’ → ‘${PREFIX}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop’"
# and the (example) magic pattern (if all else fails, copy to ~/.magic)
# TODO on Fedora concat to /usr/${LOCAL}/share/misc/magic and then recompile
	 @install -m 644 -D -T etc/magic ${PREFIX}/usr/${LOCAL}/share/encrypt/magic
	-@echo -e "installed ‘etc/magic’ → ‘${PREFIX}/usr/${LOCAL}/share/encrypt/magic’"
# and finally the auto-complete scripts
	 @install -m 755 -D -T etc/autocomplete.bash ${PREFIX}/usr/${LOCAL}/share/bash-completion/completions/encrypt
	-@echo -e "installed ‘etc/autocomplete.bash’ → ‘${PREFIX}/usr/${LOCAL}/share/bash-completion/completions/encrypt’"
	 @install -m 755 -D -T etc/autocomplete.zsh ${PREFIX}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt
	-@echo -e "installed ‘etc/autocomplete.zsh’ → ‘${PREFIX}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt’"

uninstall:
	@rm -fvr ${PREFIX}/usr/${LOCAL}/share/encrypt
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/bash-completion/completions/encrypt
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt.svg
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/applications/encrypt.desktop
	@rm -fv ${PREFIX}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop
	@rm -fv ${PREFIX}/usr/bin/${ALT}
	@rm -fv ${PREFIX}/usr/bin/${APP}

clean:
	@rm -fv ${APP} ${ALT}
	@rm -fv gmon.out

distclean: clean
	@rm -fv ${APP}.1a.gz
	@rm -fvr pkg build
	@rm -fv ${APP}*.pkg.tar.xz
	@rm -fv ${APP}*.tgz
