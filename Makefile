.PHONY: clean distclean

APP      = encrypt

SOURCE   = src/main.c src/init.c src/encrypt.c src/io.c
GUI      = src/gui.c
COMMON   = src/common/error.c src/common/logging.c

CFLAGS   = -Wall -Wextra -Wno-unused-parameter -std=gnu99 `libgcrypt-config --cflags` -pipe -O2
CPPFLAGS = -I. -Isrc -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DLOG_DEFAULT=LOG_WARNING
GUIFLAGS = -DBUILD_GUI -D__DEBUG_GUI__ `pkg-config --cflags gtk+-3.0 gmodule-2.0`

LIBS     = `libgcrypt-config --libs` -lpthread -lcurl -llzma
GUILIBS  = `pkg-config --libs gtk+-3.0 gmodule-2.0`

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
	@gzip -c docs/encrypt.1a > encrypt.1a.gz
	@echo "compressing \`docs/encrypt.1a' --> \`encrypt.1a.gz"

install:
# install the main executible, then softlink to it from /usr/bin
	 @install -c -m 755 -s -D -T encrypt $(PREFIX)/usr/bin/encrypt
	-@echo "installed \`encrypt' --> \`$(PREFIX)/usr/bin/encrypt'"
# install the pixmaps
	 @install -c -m 644 -D -T pixmaps/encrypt.png $(PREFIX)/usr/share/pixmaps/encrypt.png
	-@echo "installed \`pixmaps/encrypt.png' --> \`$(PREFIX)/usr/share/pixmaps/encrypt.png'" 
	 @install -c -m 644 -D -T pixmaps/encrypt.svg $(PREFIX)/usr/share/pixmaps/encrypt.svg
	-@echo "installed \`pixmaps/encrypt.svg' --> \`$(PREFIX)/usr/share/pixmaps/encrypt.svg'" 
# next encrypt.glade
	 @install -c -m 644 -D -T encrypt.glade $(PREFIX)/usr/share/encrypt/encrypt.glade
	-@echo "installed \`encrypt.glade' --> \`$(PREFIX)/usr/share/encrypt/encrypt.glade'" 
# ditto, but this time for the man page
	 @install -c -m 644 -D -T encrypt.1a.gz $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	-@echo "installed \`encrypt.1a.gz' --> \`$(PREFIX)/usr/share/man/man1/encrypt.1a.gz'"
# and then the desktop file
	 @install -c -m 644 -D -T encrypt.desktop $(PREFIX)/usr/share/applications/encrypt.desktop
	-@echo "installed \`encrypt.desktop' --> \`$(PREFIX)/usr/share/applications/encrypt.desktop'"
# and finally the magic pattern
	 @install -c -m 644 -D -T docs/magic $(PREFIX)/usr/share/file/magic/encrypt
	-@echo "installed \`docs/magic' --> \`$(PREFIX)/usr/share/file/magic/encrypt'"
	 @file -C && mv magic.mgc /usr/share/file/magic.mgc
	-@echo "compiled updated magic pattern file"

uninstall:
	@rm -fvr $(PREFIX)/usr/share/encrypt
	#@rm -fv $(PREFIX)/usr/share/file/magic/encrypt
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt.svg
	@rm -fv $(PREFIX)/usr/share/pixmaps/encrypt.png
	@rm -fv $(PREFIX)/usr/share/man/man1/encrypt.1a.gz
	@rm -fv $(PREFIX)/usr/share/applications/encrypt.desktop
	@rm -fv $(PREFIX)/usr/bin/encrypt

clean:
	@rm -fv $(APP)

distclean: clean
	@rm -fv encrypt.1a.gz
#	@$(MAKE) -C po distclean
