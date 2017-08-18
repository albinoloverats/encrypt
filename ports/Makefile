# $FreeBSD$

PORTNAME=     encrypt
DISTVERSION=  2017.09
CATEGORIES=   security
MASTER_SITES= https://albinoloverats.net/downloads/${DISTNAME}/${DISTVERSION}/
DISTNAME=     encrypt
EXTRACT_SUFX= .tar.xz
DISTFILES=    ${DISTNAME}-${DISTVERSION}${EXTRACT_SUFX}

MAINTAINER=   amanderson@albinoloverats.net
COMMENT=      Provid simple, cross platform, file encryption

LICENSE=      GPLv3+

USES=         desktop-file-utils gettext

USE_GNOME=    pango atk cairo gdkpixbuf2 glib20

LIB_DEPENDS=  libgcrypt.so:security/libgcrypt libgpg-error.so:security/libgpg-error libgtk-3.so:x11-toolkits/gtk30 libcurl.so:ftp/curl liblzma.so:archivers/lzma

.include <bsd.port.mk>
