.PHONY: helloworld install-helloworld clean-helloworld uninstall-helloworld

LIB_MAKE      += helloworld
LIB_INSTALL   += install-helloworld
LIB_CLEAN     += clean-helloworld
LIB_UNINSTALL += uninstall-helloworld

helloworld:
	 @gcc -o helloworld.so -std=gnu99 -Os -fPIC -Wall -Wextra -pipe -D_GNU_SOURCE -shared -Wl,-soname,helloworld.so lib/helloworld.c
	-@echo "compiled \`lib/helloworld.c' --> \`helloworld.so'"

install-helloworld:
	 @install -c -m 755 -s -D -T helloworld.so ${PREFIX}/usr/lib/encrypt/lib/helloworld.so
	 @ln -fs ${PREFIX}/usr/lib/encrypt/lib/helloworld.so ${PREFIX}/usr/lib/
	-@echo "installed \`helloworld.so' --> \`${PREFIX}/usr/lib/encrypt/lib/helloworld.so'"

clean-helloworld:
	-@rm -fv helloworld.so

uninstall-helloworld:
	-@rm -fv ${PREFIX}/usr/lib/helloworld.so ${PREFIX}/usr/lib/encrypt/lib/helloworld.so

