# Maintainer: Ashley Anderson <amanderson@albinoloverats.net>
# Contributor: Ashley Anderson <amanderson@albinoloverats.net>
pkgname=encrypt
pkgver=2013.02
pkgrel=1
pkgdesc=(A simple, cross platform, file encryption application---suitable for any modern desktop or mobile operating system. The GUI, either GTK or native, has been desigen to be common across systems and intuitive to use, whilst still providing command-line capabilities for power-users.)
arch=(any)
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
