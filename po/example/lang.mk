.PHONY:

PO_MAKE      += lang
PO_INSTALL   += install-lang
PO_CLEAN     += clean-lang
PO_UNINSTALL += uninstall-lang

lang:
	 @msgfmt po/lang.po common/po/de.po -o lang.mo
	-@echo "generated \`po/lang.po' --> \`lang.mo'"

#install-lang:
#	 @install -c -m 644 -D -T lang.mo $(PREFIX)/usr/lib/encrypt/po/lang.mo
#	 @ln -fs /usr/lib/encrypt/po/lang.mo $(PREFIX)/usr/share/locale/de/LC_MESSAGES/encrypt.mo
#	-@echo "installed \`lang.mo' --> \`$(PREFIX)/usr/lib/encrypt/po/lang.mo'"

clean-lang:
	-@rm -fv lang.mo

#uninstall-lang:
#	-@rm -fv $(PREFIX)/usr/share/locale/lang/LC_MESSAGES/encrypt.mo $(PREFIX)/usr/lib/encrypt/po/lang.mo
