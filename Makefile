.PHONY: clean distclean

APP      = encrypt
ALT		 = decrypt

SOURCE   = src/main.c src/init.c src/crypt.c src/encrypt.c src/decrypt.c src/crypt_io.c
GUI      = src/gui-gtk.c
COMMON   = src/common/error.c src/common/tlv.c src/common/version.c src/common/fs.c src/common/cli.c src/common/dir.c

CFLAGS  += -Wall -Wextra -std=gnu99 `libgcrypt-config --cflags` -pipe -O2
CPPFLAGS = -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DGCRYPT_NO_DEPRECATED -DGIT_COMMIT=\"`git log | head -n1 | cut -f2 -d' '`\"
GUIFLAGS = -DBUILD_GUI `pkg-config --cflags gtk+-3.0 gmodule-2.0`

DEBUG    = -O0 -ggdb -D__DEBUG__ -D__DEBUG_GUI__

LIBS     = `libgcrypt-config --libs` -lpthread -lcurl -llzma
GUILIBS  = `pkg-config --libs gtk+-3.0 gmodule-2.0`

all: gui language man

cli: link
	 @$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) -o $(APP)
	-@echo -e "built ‘`echo -e $(SOURCE) $(COMMON) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

debug: link
	 @$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) $(DEBUG) -o $(APP)
	-@echo -e "built ‘`echo -e $(SOURCE) $(COMMON) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

debug-with-encryption: link
	 @$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) $(DEBUG) -D__DEBUG_WITH_ENCRYPTION__ -o $(APP)
	-@echo -e "built ‘`echo -e $(SOURCE) $(COMMON) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

gui: link
	 @$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) -o $(APP)
	-@echo -e "built ‘`echo -e $(SOURCE) $(COMMON) $(GUI) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

debug-gui: link
	 @$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) $(DEBUG) -o $(APP)
	-@echo -e "built ‘`echo -e $(SOURCE) $(COMMON) $(GUI) | sed 's/ /’\n      ‘/g'`’ → ‘$(APP)’"

link:
	 @ln -fs $(APP) $(ALT)
	-@echo -e "linked ‘$(ALT)’ → ‘$(APP)’"

language:
	-@echo -e "TODO - string translation"
#	@$(MAKE) -C po

man:
	 @gzip -c docs/$(APP).1a > $(APP).1a.gz
	-@echo -e "compressing ‘docs/$(APP).1a’ → ‘$(APP).1a.gz"

install:
# install the main executable, also link decrypt
	 @install -c -m 755 -s -D -T $(APP) $(PREFIX)/usr/bin/$(APP)
	-@echo -e "installed ‘$(APP)’ → ‘$(PREFIX)/usr/bin/$(APP)’"
	 @ln -f ${PREFIX}/usr/bin/$(APP) ${PREFIX}/usr/bin/$(ALT)
	-@echo -e "linked ‘$(ALT)’ → ‘$(APP)’"
# install the pixmaps
	 @install -c -m 644 -D -T pixmaps/encrypt.svg $(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt.svg
	-@echo -e "installed ‘pixmaps/encrypt.svg’ → ‘$(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt.svg’"
	 @install -c -m 644 -D -T pixmaps/encrypt_button.svg $(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt_button.svg
	-@echo -e "installed ‘pixmaps/encrypt_button.svg’ → ‘$(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt_button.svg’"
# next encrypt.glade
	 @install -c -m 644 -D -T etc/encrypt.glade $(PREFIX)/usr/$(LOCAL)/share/encrypt/encrypt.glade
	-@echo -e "installed ‘etc/encrypt.glade’ → ‘$(PREFIX)/usr/$(LOCAL)/share/encrypt/encrypt.glade’"
# and an example rc file
	 @install -c -m 644 -D -T etc/encryptrc $(PREFIX)/usr/$(LOCAL)/share/encrypt/encryptrc
	-@echo -e "installed ‘etc/encryptrc’ → ‘$(PREFIX)/usr/$(LOCAL)/share/encrypt/encryptrc’"
# ditto, but this time for the man page
	 @install -c -m 644 -D -T encrypt.1a.gz $(PREFIX)/usr/$(LOCAL)/share/man/man1/encrypt.1a.gz
	-@echo -e "installed ‘encrypt.1a.gz’ → ‘$(PREFIX)/usr/$(LOCAL)/share/man/man1/encrypt.1a.gz’"
# and then the desktop files
	 @install -c -m 644 -D -T etc/encrypt.desktop $(PREFIX)/usr/$(LOCAL)/share/applications/encrypt.desktop
	-@echo -e "installed ‘etc/encrypt.desktop’ → ‘$(PREFIX)/usr/$(LOCAL)/share/applications/encrypt.desktop’"
	 @install -c -m 644 -D -T etc/thunar-sendto.desktop $(PREFIX)/usr/$(LOCAL)/share/Thunar/sendto/encrypt.desktop
	-@echo -e "installed ‘etc/thunar-sendto.desktop’ → ‘$(PREFIX)/usr/$(LOCAL)/share/Thunar/sendto/encrypt.desktop’"
# and the (example) magic pattern (if all else fails, copy to ~/.magic)
# TODO on Fedora concat to /usr/$(LOCAL)/share/misc/magic and then recompile
	 @install -c -m 644 -D -T etc/magic $(PREFIX)/usr/$(LOCAL)/share/encrypt/magic
	-@echo -e "installed ‘etc/magic’ → ‘$(PREFIX)/usr/$(LOCAL)/share/encrypt/magic’"
# and finally the auto-complete scripts
	 @install -c -m 755 -D -T etc/autocomplete.bash $(PREFIX)/usr/$(LOCAL)/share/bash-completion/completions/encrypt
	-@echo -e "installed ‘etc/autocomplete.bash’ → ‘$(PREFIX)/usr/$(LOCAL)/share/bash-completion/completions/encrypt’"
	 @install -c -m 755 -D -T etc/autocomplete.zsh $(PREFIX)/usr/$(LOCAL)/share/zsh/functions/Completion/Unix/_encrypt
	-@echo -e "installed ‘etc/autocomplete.zsh’ → ‘$(PREFIX)/usr/$(LOCAL)/share/zsh/functions/Completion/Unix/_encrypt’"

uninstall:
	@rm -fvr $(PREFIX)/usr/$(LOCAL)/share/encrypt
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/bash-completion/completions/encrypt
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/zsh/functions/Completion/Unix/_encrypt
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt.svg
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/pixmaps/encrypt_button.svg
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/man/man1/encrypt.1a.gz
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/applications/encrypt.desktop
	@rm -fv $(PREFIX)/usr/$(LOCAL)/share/Thunar/sendto/encrypt.desktop
	@rm -fv $(PREFIX)/usr/bin/$(ALT)
	@rm -fv $(PREFIX)/usr/bin/$(APP)

clean:
	@rm -fv $(APP)
	@rm -fv $(ALT)

distclean: clean
	@rm -fv $(APP).1a.gz
	@rm -fvr pkg build
	@rm -fv $(APP)*.pkg.tar.xz
	@rm -fv $(APP)*.tgz
