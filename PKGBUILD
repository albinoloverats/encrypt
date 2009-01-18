# Contributor: Ashley Anderson <amanderson@albinoloverats.net>
pkgname=encrypt
pkgver=200901
pkgrel=1
pkgdesc="A simple, X-platform, plugin-based encryption application"
arch=(i686 x86_64)
url="https://albinoloverats.net/encrypt"
license=('GPL')
groups=()
depends=('glibc gtk2')
makedepends=('pkgconfig')
provides=()
conflicts=()
replaces=()
backup=()
options=()
install=
source=($pkgname-$pkgver.tar.bz2)
noextract=()
md5sums=()

build() {
  mkdir -p ${startdir}/pkg/usr/{bin,lib,man/man1}
  cd $startdir/$pkgname-$pkgver
  make all
  make install-all PREFIX=$startdir/pkg/
}
