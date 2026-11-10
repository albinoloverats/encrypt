.PHONY: crack clean distclean test

APP            = encrypt
ALT            = decrypt
CRK            = crack

COMMON_SRC     = common/src/error.c common/src/mem.c common/src/ccrypt.c common/src/list.c common/src/tlv.c common/src/version.c common/src/config.c common/src/cli.c common/src/dir.c common/src/ecc.c common/src/non-gnu.c
CLI_SRC        = ${COMMON_SRC} src/main.c src/crypt.c src/encrypt.c src/decrypt.c src/crypt_io.c
GUI_SRC        = ${CLI_SRC} src/gui-gtk.c
CRK_SRC        = ${COMMON_SRC} src/crypt_io.c src/crypt.c C-Thread-Pool/thpool.c src/crack.c
CORE_SRC       = ${COMMON_SRC} src/crypt.c src/encrypt.c src/decrypt.c src/crypt_io.c
MISC           = src/misc.h
IO_TEST        = test-crypt-io
FLOW_TEST      = test-crypt-flow

BUILD_OS       = $(shell . /etc/os-release && printf '%s' "$$PRETTY_NAME")

CLI_CFLAGS     = ${CFLAGS} -Wall -Wextra -std=gnu99 $(shell pkg-config --cflags libgcrypt) -pipe -O2 -Wrestrict -Wformat=2 -Wno-unused-result
CLI_CPPFLAGS   = ${CPPFLAGS} -Isrc -Icommon -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DGCRYPT_NO_DEPRECATED -DUSE_GCRYPT
GUI_CFLAGS     = ${CLI_CFLAGS} $(shell pkg-config --cflags gtk+-3.0 gmodule-2.0)
GUI_CPPFLAGS   = ${CLI_CPPFLAGS} -DBUILD_GUI
CRK_CPPFLAGS   = ${CLI_CPPFLAGS} -IC-Thread-Pool
TEST_CFLAGS    = ${CLI_CFLAGS} --coverage $(shell pkg-config --cflags cmocka)

DEBUG_CFLAGS   = -O0 -ggdb -pg
DEBUG_CPPFLAGS = -D__DEBUG__ -D__DEBUG_GUI__ -DMALLOC_CHECK_=1
DEBUG_ENC      = ${DEBUG_CPPFLAGS} -D__DEBUG_WITH_ENCRYPTION__

CLI_LIBS       = $(shell pkg-config --libs libgcrypt) -lpthread -lcurl -llzma
GUI_LIBS       = ${CLI_LIBS} $(shell pkg-config --libs gtk+-3.0 gmodule-2.0)
CRK_LIBS       = ${CLI_LIBS} -lgmp
TEST_LIBS      = ${CLI_LIBS} $(shell pkg-config --libs cmocka)
GCOV           = $(shell command -v gcov-$(shell ${CC} -dumpversion | cut -d. -f1) || ${CC} -print-prog-name=gcov)

VERSION_SH     = scripts/version.sh

all: gui symlink language man

debug: cli-debug symlink

symlink:
	 @ln -fs ${APP} ${ALT}
	-@echo -e "linked ‘${ALT}’ → ‘${APP}’"

cli: symlink
	 @sh ${VERSION_SH} "$(strip ${CLI_CFLAGS})" "$(strip ${CLI_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${CLI_SRC} ${CLI_LIBS} -o ${APP}
	-@echo -e "built ‘`echo -e ${CLI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

test: clean symlink
	 @sh ${VERSION_SH} "$(strip ${TEST_CFLAGS})" "$(strip ${CLI_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${TEST_CFLAGS} ${CLI_CPPFLAGS} ${CLI_SRC} ${CLI_LIBS} -o ${APP}
	-@echo -e "built ‘`echo -e ${CLI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"
ifneq ($(strip ${CMOCKA_XML_DIR}),)
	 @mkdir -p "${CMOCKA_XML_DIR}"
	 @CMOCKA_MESSAGE_OUTPUT=XML CMOCKA_XML_FILE="$(abspath ${CMOCKA_XML_DIR})/common.xml" ${MAKE} -C common test CMOCKA_XML_DIR="$(abspath ${CMOCKA_XML_DIR})"
else
	 @${MAKE} -C common test
endif
	-@echo Finished common tests

	 @sh ${VERSION_SH} "$(strip ${TEST_CFLAGS})" "$(strip ${CLI_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${TEST_CFLAGS} ${CLI_CPPFLAGS} ${CORE_SRC} test/test_crypt_io.c ${TEST_LIBS} -o ${IO_TEST}
	-@echo -e "built ‘`echo -e ${CORE_SRC} test/test_crypt_io.c | sed 's/ /’\n      ‘/g'`’ → ‘${IO_TEST}’"
ifneq ($(strip ${CMOCKA_XML_DIR}),)
	 @mkdir -p "${CMOCKA_XML_DIR}"
	 @CMOCKA_MESSAGE_OUTPUT=XML CMOCKA_XML_FILE="$(abspath ${CMOCKA_XML_DIR})/${IO_TEST}.xml" ./${IO_TEST}
else
	 @./${IO_TEST}
endif
	-@echo Finished ${IO_TEST} tests

	 @sh ${VERSION_SH} "$(strip ${TEST_CFLAGS})" "$(strip ${CLI_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${TEST_CFLAGS} ${CLI_CPPFLAGS} ${CORE_SRC} test/test_crypt_flow.c ${TEST_LIBS} -o ${FLOW_TEST}
	-@echo -e "built ‘`echo -e ${CORE_SRC} test/test_crypt_flow.c | sed 's/ /’\n      ‘/g'`’ → ‘${FLOW_TEST}’"
ifneq ($(strip ${CMOCKA_XML_DIR}),)
	 @CMOCKA_MESSAGE_OUTPUT=XML CMOCKA_XML_FILE="$(abspath ${CMOCKA_XML_DIR})/${FLOW_TEST}.xml" ./${FLOW_TEST}
else
	 @./${FLOW_TEST}
endif
	-@echo Finished ${FLOW_TEST} tests

	 @sh test/test_cli_compressed_eof.sh
	-@echo Finished EOF tests
#	 @mkdir -p coverage
#	 @gcovr --root . --gcov-executable "${GCOV}" --filter 'src/' --filter 'common/src/' --xml-pretty --output coverage/coverage.xml --html-details coverage/index.html --print-summary

cli-debug:
	 @sh ${VERSION_SH} "$(strip ${CLI_CFLAGS} ${DEBUG_CFLAGS})" "$(strip ${CLI_CPPFLAGS} ${DEBUG_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${CLI_SRC} ${CLI_LIBS} ${DEBUG_CFLAGS} ${DEBUG_CPPFLAGS} -o ${APP}
	-@echo -e "built ‘`echo -e ${CLI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

cli-debug-with-encryption:
	 @sh ${VERSION_SH} "$(strip ${CLI_CFLAGS} ${DEBUG_CFLAGS})" "$(strip ${CLI_CPPFLAGS} ${DEBUG_ENC})" "${BUILD_OS}"
	 @${CC} ${CLI_CFLAGS} ${CLI_CPPFLAGS} ${CLI_SRC} ${CLI_LIBS} ${DEBUG_CFLAGS} ${DEBUG_ENC}      -o ${APP}
	-@echo -e "built ‘`echo -e ${CLI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui:
	 @sh ${VERSION_SH} "$(strip ${GUI_CFLAGS})" "$(strip ${GUI_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${GUI_SRC} ${GUI_LIBS} -o ${APP}
	-@echo -e "built ‘`echo -e ${GUI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui-debug:
	 @sh ${VERSION_SH} "$(strip ${GUI_CFLAGS} ${DEBUG_CFLAGS})" "$(strip ${GUI_CPPFLAGS} ${DEBUG_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${GUI_SRC} ${GUI_LIBS} ${DEBUG_CFLAGS} ${DEBUG_CPPFLAGS} -o ${APP}
	-@echo -e "built ‘`echo -e ${GUI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

gui-debug-with-encryption:
	 @sh ${VERSION_SH} "$(strip ${GUI_CFLAGS} ${DEBUG_CFLAGS})" "$(strip ${GUI_CPPFLAGS} ${DEBUG_ENC})" "${BUILD_OS}"
	 @${CC} ${GUI_CFLAGS} ${GUI_CPPFLAGS} ${GUI_SRC} ${GUI_LIBS} ${DEBUG_CFLAGS} ${DEBUG_ENC}      -o ${APP}
	-@echo -e "built ‘`echo -e ${GUI_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${APP}’"

crack:
	 @sh ${VERSION_SH} "$(strip ${CLI_CFLAGS} ${DEBUG_CFLAGS})" "$(strip ${CRK_CPPFLAGS} ${DEBUG_CPPFLAGS})" "${BUILD_OS}"
	 @${CC} ${CLI_CFLAGS} ${CRK_CPPFLAGS} ${CRK_SRC} ${CRK_LIBS} ${DEBUG_CFLAGS} ${DEBUG_CPPFLAGS} -o ${CRK}
	-@echo -e "built ‘`echo -e ${CRK_SRC} | sed 's/ /’\n      ‘/g'`’ → ‘${CRK}’"

language:
	-@echo -e "TODO - string translation"
#	@${MAKE} -C po

man:
	 @gzip -c docs/${APP}.1a > ${APP}.1a.gz
	-@echo -e "compressing ‘docs/${APP}.1a’ → ‘${APP}.1a.gz"

install:
# install the main executable, also link decrypt
	 @install -m 755 -s -D -T ${APP} ${DESTDIR}/usr/bin/${APP}
	-@echo -e "installed ‘${APP}’ → ‘${DESTDIR}/usr/bin/${APP}’"
	 @ln -f ${DESTDIR}/usr/bin/${APP} ${DESTDIR}/usr/bin/${ALT}
	-@echo -e "linked ‘${ALT}’ → ‘${APP}’"
# install the pixmaps
	 @install -m 644 -D -T pixmaps/encrypt.svg ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt.svg
	-@echo -e "installed ‘pixmaps/encrypt.svg’ → ‘${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt.svg’"
	 @install -m 644 -D -T pixmaps/encrypt_button.svg ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg
	-@echo -e "installed ‘pixmaps/encrypt_button.svg’ → ‘${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg’"
	 @install -m 644 -D -T pixmaps/encrypt_key.png ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_key.png
	-@echo -e "installed ‘pixmaps/encrypt_key.png’ → ‘${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_key.png’"
# next encrypt.glade
	 @install -m 644 -D -T etc/encrypt.glade ${DESTDIR}/usr/${LOCAL}/share/encrypt/encrypt.glade
	-@echo -e "installed ‘etc/encrypt.glade’ → ‘${DESTDIR}/usr/${LOCAL}/share/encrypt/encrypt.glade’"
# and an example rc file
	 @install -m 644 -D -T etc/encryptrc ${DESTDIR}/usr/${LOCAL}/share/encrypt/encryptrc
	-@echo -e "installed ‘etc/encryptrc’ → ‘${DESTDIR}/usr/${LOCAL}/share/encrypt/encryptrc’"
# ditto, but this time for the man page
	 @install -m 644 -D -T encrypt.1a.gz ${DESTDIR}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz
	-@echo -e "installed ‘encrypt.1a.gz’ → ‘${DESTDIR}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz’"
# and then the desktop files
	 @install -m 644 -D -T etc/encrypt.desktop ${DESTDIR}/usr/${LOCAL}/share/applications/encrypt.desktop
	-@echo -e "installed ‘etc/encrypt.desktop’ → ‘${DESTDIR}/usr/${LOCAL}/share/applications/encrypt.desktop’"
	 @install -m 644 -D -T etc/thunar-sendto.desktop ${DESTDIR}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop
	-@echo -e "installed ‘etc/thunar-sendto.desktop’ → ‘${DESTDIR}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop’"
# and the (example) magic pattern (if all else fails, copy to ~/.magic)
# TODO on Fedora concat to /usr/${LOCAL}/share/misc/magic and then recompile
	 @install -m 644 -D -T etc/magic ${DESTDIR}/usr/${LOCAL}/share/encrypt/magic
	-@echo -e "installed ‘etc/magic’ → ‘${DESTDIR}/usr/${LOCAL}/share/encrypt/magic’"
# and finally the auto-complete scripts
	 @install -m 755 -D -T etc/autocomplete.bash ${DESTDIR}/usr/${LOCAL}/share/bash-completion/completions/encrypt
	-@echo -e "installed ‘etc/autocomplete.bash’ → ‘${DESTDIR}/usr/${LOCAL}/share/bash-completion/completions/encrypt’"
	 @install -m 755 -D -T etc/autocomplete.zsh ${DESTDIR}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt
	-@echo -e "installed ‘etc/autocomplete.zsh’ → ‘${DESTDIR}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt’"

uninstall:
	 @rm -fvr ${DESTDIR}/usr/${LOCAL}/share/encrypt
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/bash-completion/completions/encrypt
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/zsh/functions/Completion/Unix/_encrypt
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt.svg
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_button.svg
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/pixmaps/encrypt_key.png
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/man/man1/encrypt.1a.gz
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/applications/encrypt.desktop
	 @rm -fv ${DESTDIR}/usr/${LOCAL}/share/Thunar/sendto/encrypt.desktop
	 @rm -fv ${DESTDIR}/usr/bin/${ALT}
	 @rm -fv ${DESTDIR}/usr/bin/${APP}

clean:
	 @rm -fv ${MISC}
	 @rm -fv ${APP} ${ALT} ${CRK} ${IO_TEST} ${FLOW_TEST}
	 @rm -fv *.gcda *.gcno
	 @rm -fvr coverage
	 @rm -fv gmon.out
	 @${MAKE} -C common clean

distclean: clean
	 @rm -fv ${APP}.1a.gz
	 @rm -fvr pkg build
	 @rm -fv ${APP}*.pkg.tar.xz
	 @rm -fv ${APP}*.pkg.tar.zst
	 @rm -fv ${APP}*.tgz
