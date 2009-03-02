# Contributor: Ashley Anderson <amanderson@albinoloverats.net>
pkgname=encrypt
pkgver=200903
pkgrel=1
pkgdesc="A simple, X-platform, plugin-based encryption application encrypt is a simple encryption application which is suitable for any modern OS. It uses the GTK to provide a graphical user interface, yet is equally usable from the command line. Plugins allow additional algorithms to be chosen by the user at runtime."
arch=(i686 x86_64)
url="https://albinoloverats.net/encrypt"
license=('GPL')
groups=()
depends=('gtk2')
makedepends=('pkgconfig')
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
  mkdir -p pkg/usr/{bin,lib,man/man1,share/applications}
  make -f Makefile.gnu gui-all
  make -f Makefile.gnu install-all PREFIX=pkg
}
