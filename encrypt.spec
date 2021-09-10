Summary: A simple, X-platform, encryption application
Name: encrypt
Version: 2021.10
Release: 1
Source: https://albinoloverats.net/downloads/%{name}.tar.xz
URL: https://albinoloverats.net/projects/%{name}
License: GPL
BuildRoot: /var/tmp/%{name}
Group: Applications/File
Requires: libgcrypt, gtk3, libcurl, xz

%description
A simple, cross platform, file encryption application---suitable for any
modern desktop or mobile operating system. The GUI, either GTK or
native, has been desigen to be common across systems and intuitive to
use, whilst still providing command-line capabilities for power-users.

%global debug_package %{nil}

%prep
%setup -q

%build
make -f Makefile all OS_OPTS=-DFEDORA_PATH_HACK

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/{bin,share/{encrypt,applications,man/man1,pixmaps,bash-completion/completions,zsh/functions/Completion/Unix}}
make install PREFIX=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/usr/bin/encrypt
/usr/bin/decrypt
/usr/share/encrypt/encrypt.glade
/usr/share/encrypt/magic
/usr/share/encrypt/encryptrc
/usr/share/applications/encrypt.desktop
/usr/share/Thunar/sendto/encrypt.desktop
/usr/share/man/man1/encrypt.1a.gz
/usr/share/pixmaps/encrypt.svg
/usr/share/pixmaps/encrypt_button.svg
/usr/share/bash-completion/completions/encrypt
/usr/share/zsh/functions/Completion/Unix/_encrypt
