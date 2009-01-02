.PHONY: anubis install-anubis clean-anubis uninstall-anubis

LIB_MAKE      += anubis
LIB_INSTALL   += install-anubis
LIB_CLEAN     += clean-anubis
LIB_UNINSTALL += uninstall-anubis

anubis:
	 @gcc -o anubis.so -std=c99 -Os -fPIC -Wall -Wextra -pipe -D_GNU_SOURCE -shared -Wl,-soname,anubis.so lib/anubis.c lib/rmd160.c
	-@echo "compiled \`lib/anubis.c' --> \`anubis.so'"

install-anubis:
	 @install -c -m 755 -s -D -T anubis.so $(PREFIX)/usr/lib/encrypt/lib/anubis.so
	 @ln -fs /usr/lib/encrypt/lib/anubis.so $(PREFIX)/usr/lib/
	-@echo "installed \`anubis.so' --> \`$(PREFIX)/usr/lib/encrypt/lib/anubis.so'"

clean-anubis:
	-@rm -fv anubis.so

uninstall-anubis:
	-@rm -fv /usr/lib/anubis.so $(PREFIX)/usr/lib/encrypt/lib/anubis.so

