.PHONY: serpent install-serpent clean-serpent uninstall-serpent

LIB_MAKE      += serpent
LIB_INSTALL   += install-serpent
LIB_CLEAN     += clean-serpent
LIB_UNINSTALL += uninstall-serpent

serpent:
	 @gcc -o serpent.so -std=c99 -Os -fPIC -Wall -Wextra -pipe -D_GNU_SOURCE -shared -Wl,-soname,serpent.so lib/serpent.c lib/tiger.c lib/serpent_sboxes.c
	-@echo "compiled \`lib/serpent.c' --> \`serpent.so'"

install-serpent:
	 @install -c -m 755 -s -D -T serpent.so $(PREFIX)/usr/lib/encrypt/lib/serpent.so
	 @ln -fs /usr/lib/encrypt/lib/serpent.so $(PREFIX)/usr/lib/
	-@echo "installed \`serpent.so' --> \`$(PREFIX)/usr/lib/encrypt/lib/serpent.so'"

clean-serpent:
	-@rm -fv serpent.so

uninstall-serpent:
	-@rm -fv $(PREFIX)/usr/lib/serpent.so $(PREFIX)/usr/lib/encrypt/lib/serpent.so

