# Maintainer: Ashley Anderson <amanderson@albinoloverats.net>
# Contributor: Ashley Anderson <amanderson@albinoloverats.net>
pkgname=encrypt
pkgver=2012.11
pkgrel=1
pkgdesc=(A simple encryption application which is suitable for any modern OS. It uses the GTK to provide a graphical user interface, yet is equally usable from the command line.)
arch=(i686 x86_64)
url=(https://albinoloverats.net/projects/encrypt)
license=(GPL)
groups=()
depends=(libgcrypt gtk3 curl xz)
makedepends=(pkgconfig)
provides=()
conflicts=()
replaces=()
backup=()
options=()
install=
source=()
noextract=()
md5sums=()

build() {
  cd ..
  mkdir -p pkg/usr/{bin,share/{encrypt,applications,man/man1,pixmaps,file/magic,bash-completion/completions,zsh/functions/Completion/Unix}} # ,locale/de/LC_MESSAGES}}
  make -f Makefile all
  make -f Makefile install PREFIX=pkg
}
