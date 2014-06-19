.PHONY: clean distclean

APP      = encrypt

SOURCE   = src/main.c src/cli.c src/init.c src/crypto.c src/encrypt.c src/decrypt.c src/cryptio.c
GUI      = src/gui-gtk.c
COMMON   = src/common/error.c src/common/tlv.c src/common/version.c src/common/fs.c

CFLAGS   = -Wall -Wextra -Werror -std=gnu99 `libgcrypt-config --cflags` -pipe -O2
CPPFLAGS = -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DLOG_DEFAULT=LOG_ERROR -DGIT_COMMIT=\"`git log | head -n1 | cut -f2 -d' '`\"
GUIFLAGS = -DBUILD_GUI `pkg-config --cflags gtk+-3.0 gmodule-2.0`

DEBUG   = -O0 -ggdb -D__DEBUG__ -D__DEBUG_GUI__

LIBS     = `libgcrypt-config --libs` -lpthread -lcurl -llzma
GUILIBS  = `pkg-config --libs gtk+-3.0 gmodule-2.0`

all: gui language man

cli:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) -o $(APP)
	-@echo "built ‘`echo $(SOURCE) $(COMMON) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

debug:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) $(DEBUG) -o $(APP)
	-@echo "built ‘`echo $(SOURCE) $(COMMON) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

gui:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) -o $(APP)
	-@echo "built ‘`echo $(SOURCE) $(COMMON) $(GUI) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"
debug-gui:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) $(DEBUG) -o $(APP)
	-@echo "built ‘`echo $(SOURCE) $(COMMON) $(GUI) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

language:
	-@echo "TODO - string translation"
#	@$(MAKE) -C po

man:
	@gzip -c docs/encrypt.1a > encrypt.1a.gz
	-@echo "compressing ‘docs/encrypt.1a’ → ‘encrypt.1a.gz"

install: man
# install the main executable, also link decrypt
	 @install -c -m 755 -s -D -T encrypt $(PREFIX)/usr/bin/encrypt
	-@echo "installed ‘encrypt’ → ‘$(PREFIX)/usr/bin/encrypt’"
	 @ln -f ${PREFIX}/usr/bin/encrypt ${PREFIX}/usr/bin/decrypt
	-@echo "linked ‘decrypt’ → ‘encrypt’"
# install the pixmaps
	 @install -c -m 644 -D -T pixmaps/encrypt.svg $(PREFIX)/usr/share/pixmaps/encrypt.svg
	-@echo "installed ‘pixmaps/encrypt.svg’ → ‘$(PREFIX)/usr/share/pixmaps/encrypt.svg’"
	 @install -c -m 644 -D -T pixmaps/encrypt_button.svg $(PREFIX)/usr/share/pixmaps/encrypt_button.svg
	-@echo "installed ‘pixmaps/encrypt_button.svg’ → ‘$(PREFIX)/usr/share/pixmaps/encrypt_button.svg’"
# next encrypt.glade
	 @install -c -m 644 -D -T etc/encrypt.glade $(PREFIX)/usr/share/encrypt/encrypt.glade
	-@echo "installed ‘etc/encrypt.glade’ → ‘$(PREFIX)/usr/share/encrypt/encrypt.glade’"
# and an example rc file
	 @install -c -m 644 -D -T etc/encryptrc $(PREFIX)/usr/share/encrypt/encryptrc
	-@echo "installed ‘etc/encryptrc’ → ‘$(PREFIX)/usr/share/encrypt/encryptrc’"
# ditto, but this time for the man page
	 @install -c -m 644 -D -T encrypt.1a.gz $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	-@echo "installed ‘encrypt.1a.gz’ → ‘$(PREFIX)/usr/share/man/man1/encrypt.1a.gz’"
# and then the desktop files
	 @install -c -m 644 -D -T etc/encrypt.desktop $(PREFIX)/usr/share/applications/encrypt.desktop
	-@echo "installed ‘etc/encrypt.desktop’ → ‘$(PREFIX)/usr/share/applications/encrypt.desktop’"
	 @install -c -m 644 -D -T etc/thunar-sendto.desktop $(PREFIX)/usr/share/Thunar/sendto/encrypt.desktop
	-@echo "installed ‘etc/thunar-sendto.desktop’ → ‘$(PREFIX)/usr/share/Thunar/sendto/encrypt.desktop’"
# and the (example) magic pattern (if all else fails, copy to ~/.magic)
# TODO on Fedora concat to /usr/share/misc/magic and then recompile
	 @install -c -m 644 -D -T etc/magic $(PREFIX)/usr/share/encrypt/magic
	-@echo "installed ‘etc/magic’ → ‘$(PREFIX)/usr/share/encrypt/magic’"
# and finally the auto-complete scripts
	 @install -c -m 755 -D -T etc/autocomplete.bash $(PREFIX)/usr/share/bash-completion/completions/encrypt
	-@echo "installed ‘etc/autocomplete.bash’ → ‘$(PREFIX)/usr/share/bash-completion/completions/encrypt’"
	 @install -c -m 755 -D -T etc/autocomplete.zsh $(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt
	-@echo "installed ‘etc/autocomplete.zsh’ → ‘$(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt’"

uninstall:
	@rm -fvr $(PREFIX)/usr/share/encrypt
	@rm -fv $(PREFIX)/usr/share/bash-completion/completions/encrypt
	@rm -fv $(PREFIX)/usr/share/zsh/functions/Completion/Unix/_encrypt
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt.svg
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt_button.svg
	@rm -fv $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	@rm -fv $(PREFIX)/usr/share/applications/encrypt.desktop
	@rm -fv $(PREFIX)/usr/share/Thunar/sendto/encrypt.desktop
	@rm -fv $(PREFIX)/usr/bin/decrypt
	@rm -fv $(PREFIX)/usr/bin/encrypt

clean:
	@rm -fv $(APP)

distclean: clean
	@rm -fv encrypt.1a.gz
	@rm -fvr pkg
	@rm -fv encrypt*pkg.tar.xz
