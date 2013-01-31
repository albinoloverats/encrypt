.PHONY: clean distclean

APP      = encrypt

SOURCE   = src/main.c src/cli.c src/init.c src/crypto.c src/encrypt.c src/decrypt.c src/io.c
GUI      = src/gui-gtk.c
COMMON   = src/common/error.c src/common/logging.c src/common/tlv.c src/common/version.c

CFLAGS   = -Wall -Wextra -Werror -Wno-unused-parameter -std=gnu99 `libgcrypt-config --cflags` -pipe -O2
CPPFLAGS = -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DLOG_DEFAULT=LOG_ERROR
GUIFLAGS = -DBUILD_GUI `pkg-config --cflags gtk+-3.0 gmodule-2.0`

LIBS     = `libgcrypt-config --libs` -lpthread -lcurl -llzma
GUILIBS  = `pkg-config --libs gtk+-3.0 gmodule-2.0`

all: gui language man

cli:
	@$(CC) $(LIBS) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) -o $(APP)
	-@echo "built \`$(SOURCE) $(COMMON)' --> \`$(APP)'"

gui:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) -o $(APP)
	-@echo "built \`$(SOURCE) $(COMMON) $(GUI)' --> \`$(APP)'"

language:
	-@echo "TODO - fully translate all strings"
#	@$(MAKE) -C po

man:
	@gzip -c docs/encrypt.1a > encrypt.1a.gz
	-@echo "compressing \`docs/encrypt.1a' --> \`encrypt.1a.gz"

install: man
# install the main executible, also link decrypt
	 @install -c -m 755 -s -D -T encrypt $(PREFIX)/usr/bin/encrypt
	-@echo "installed \`encrypt' --> \`$(PREFIX)/usr/bin/encrypt'"
	 @ln -f ${PREFIX}/usr/bin/encrypt ${PREFIX}/usr/bin/decrypt
	-@echo "linked \`decrypt' --> \`encrypt'"
# install the pixmaps
	 @install -c -m 644 -D -T pixmaps/encrypt.svg $(PREFIX)/usr/share/pixmaps/encrypt.svg
	-@echo "installed \`pixmaps/encrypt.svg' --> \`$(PREFIX)/usr/share/pixmaps/encrypt.svg'" 
	 @install -c -m 644 -D -T pixmaps/encrypt_button.svg $(PREFIX)/usr/share/pixmaps/encrypt_button.svg
	-@echo "installed \`pixmaps/encrypt_button.svg' --> \`$(PREFIX)/usr/share/pixmaps/encrypt_button.svg'" 
# next encrypt.glade
	 @install -c -m 644 -D -T etc/encrypt.glade $(PREFIX)/usr/share/encrypt/encrypt.glade
	-@echo "installed \`etc/encrypt.glade' --> \`$(PREFIX)/usr/share/encrypt/encrypt.glade'" 
# ditto, but this time for the man page
	 @install -c -m 644 -D -T encrypt.1a.gz $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	-@echo "installed \`encrypt.1a.gz' --> \`$(PREFIX)/usr/share/man/man1/encrypt.1a.gz'"
# and then the desktop file
	 @install -c -m 644 -D -T etc/encrypt.desktop $(PREFIX)/usr/share/applications/encrypt.desktop
	-@echo "installed \`etc/encrypt.desktop' --> \`$(PREFIX)/usr/share/applications/encrypt.desktop'"
## and the magic pattern
#	 @install -c -m 644 -D -T etc/encrypt.mgc $(PREFIX)/usr/share/file/magic/encrypt
#	-@echo "installed \`etc/encrypt.mgc' --> \`$(PREFIX)/usr/share/file/magic/encrypt'"
#	 @file -C && mv magic.mgc /usr/share/file/magic.mgc
#	-@echo "compiled updated magic pattern file"
# and finally the auto-complete scripts
	 @install -c -m 755 -D -T etc/autocomplete.bash $(PREFIX)/usr/share/bash-completion/completions/encrypt
	-@echo "installed \`etc/autocomplete.bash' --> \`$(PREFIX)/usr/share/bash-completion/completions/encrypt'"
	 @install -c -m 755 -D -T etc/autocomplete.zsh $(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt
	-@echo "installed \`etc/autocomplete.zsh' --> \`$(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt'"

uninstall:
	@rm -fvr $(PREFIX)/usr/share/encrypt
	@rm -fv $(PREFIX)/usr/share/bash-completion/completions/encrypt
	@rm -fv $(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt
	# don't remove the magic number file (it will identify encrypted files even after encrypt is gone)
	#@rm -fv $(PREFIX)/usr/share/file/magic/encrypt
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt.svg
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt_button.svg
	@rm -fv $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	@rm -fv $(PREFIX)/usr/share/applications/encrypt.desktop
	@rm -fv $(PREFIX)/usr/bin/decrypt
	@rm -fv $(PREFIX)/usr/bin/encrypt

clean:
	@rm -fv $(APP)

distclean: clean
	@rm -fv encrypt.1a.gz
#	@$(MAKE) -C po distclean
