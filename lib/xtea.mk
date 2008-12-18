.PHONY: xtea install-xtea clean-xtea uninstall-xtea

LIB_MAKE      += xtea
LIB_INSTALL   += install-xtea
LIB_CLEAN     += clean-xtea
LIB_UNINSTALL += uninstall-xtea

xtea:
	 @gcc -o       xtea.so -std=c99 -Os -fPIC -Wall -Wextra -pipe -D_GNU_SOURCE -shared -Wl,-soname,xtea.so lib/xtea.c lib/md5.c
	-@echo "compiled \`lib/xtea.c' --> \`xtea.so'"

install-xtea:
	 @install -c -m 755 -s -D -T xtea.so ${PREFIX}/usr/lib/encrypt/lib/xtea.so
	 @ln -fs ${PREFIX}/usr/lib/encrypt/lib/xtea.so ${PREFIX}/usr/lib/
	-@echo "installed \`xtea.so' --> \`${PREFIX}/usr/lib/encrypt/lib/xtea.so'"

clean-xtea:
	-@rm -fv xtea.so

uninstall-xtea:
	-@rm -fv ${PREFIX}/usr/lib/xtea.so ${PREFIX}/usr/lib/encrypt/lib/xtea.so

