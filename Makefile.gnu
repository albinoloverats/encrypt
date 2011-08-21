.PHONY: clean distclean

APP      = encrypt

SOURCE   = src/main.c src/encrypt.c
COMMON   = common/common.c common/logging.c common/list.c common/tlv.c
GUI      = src/gui.c

CFLAGS   = -Wall -Wextra -Wno-unused-parameter -O0 -std=gnu99 `libgcrypt-config --cflags` -pipe -ggdb
CPPFLAGS = -DLOG_DEFAULT=LOG_ERROR -I. -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
GUIFLAGS = -DBUILD_GUI `pkg-config --cflags gtk+-3.0 gmodule-2.0`

LIBS     = `libgcrypt-config --libs` -lpthread
GUILIBS  = `pkg-config --libs gtk+-3.0 gmodule-2.0` -lpthread

cli:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCE) $(COMMON) $(LIBS) -o $(APP)
	@echo "built \`$(SOURCE) $(COMMON)' --> \`$(APP)'"

gui:
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(GUIFLAGS) $(SOURCE) $(COMMON) $(GUI) $(LIBS) $(GUILIBS) -o $(APP)
	@echo "built \`$(SOURCE) $(COMMON) $(GUI)' --> \`$(APP)'"

all: gui documentation language man

documentation:
	@echo "TODO - generate html/pdf from Doxygen"
#	@doxygen

language:
	@echo "TODO - fully translate all strings"
#	@$(MAKE) -C po

man:
	@gzip -c doc/encrypt.1a > encrypt.1a.gz
	@echo "compressing \`doc/encrypt.1a' --> \`encrypt.1a.gz"

install:
# install the main executible, then softlink to it from /usr/bin
	 @install -c -m 755 -s -D -T encrypt $(PREFIX)/usr/lib/encrypt/encrypt
	 @ln -fs /usr/lib/encrypt/encrypt $(PREFIX)/usr/bin/
	-@echo "installed \`encrypt' --> \`$(PREFIX)/usr/bin/encrypt'"
# install the pixmap/svg and glade xml
	 @install -c -m 644 -D -T pixmap/encrypt.png $(PREFIX)/usr/lib/encrypt/pixmap/encrypt.png
	-@echo "installed \`pixmap/encrypt.png' --> \`$(PREFIX)/usr/lib/encrypt/pixmap/encrypt.png'" 
	 @install -c -m 644 -D -T pixmap/encrypt.svg $(PREFIX)/usr/lib/encrypt/pixmap/encrypt.svg
	-@echo "installed \`pixmap/encrypt.svg' --> \`$(PREFIX)/usr/lib/encrypt/pixmap/encrypt.svg'" 
	 @install -c -m 644 -D -T encrypt.glade $(PREFIX)/usr/lib/encrypt/encrypt.glade
	 @ln -fs /usr/lib/encrypt/encrypt.glade $(PREFIX)/usr/bin/
	-@echo "installed \`encrypt.glade' --> \`$(PREFIX)/usr/lib/encrypt/encrypt.glade'" 
# ditto, but this time for the man page
	 @install -c -m 644 -D -T encrypt.1a.gz $(PREFIX)/usr/lib/encrypt/doc/encrypt.1a.gz
	 @ln -fs /usr/lib/encrypt/doc/encrypt.1a.gz $(PREFIX)/usr/man/man1/
	-@echo "installed \`encrypt.1a.gz' --> \`$(PREFIX)/usr/man/man1/encrypt.1a.gz'"
# finally the desktop file
	 @install -c -m 644 -D -T encrypt.desktop $(PREFIX)/usr/lib/encrypt/encrypt.desktop
	 @ln -fs /usr/lib/encrypt/encrypt.desktop $(PREFIX)/usr/share/applications/
	-@echo "installed \`encrypt.desktop' --> \`$(PREFIX)/usr/share/applications/encrypt.desktop'"

uninstall:
	@rm -fvr $(PREFIX)/usr/lib/encrypt
	@rm -fv $(PREFIX)/usr/man/man1/encrypt.1a.gz
	@rm -fv $(PREFIX)/usr/share/applications/encrypt.desktop
	@rm -fv $(PREFIX)/usr/bin/encrypt.glade
	@rm -fv $(PREFIX)/usr/bin/encrypt

clean:
	@rm -fv $(APP)

distclean: clean
	@rm -fv encrypt.1a.gz
#	@$(MAKE) -C po distclean
