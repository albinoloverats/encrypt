Summary: A simple, X-platform, encryption application
Name: encrypt
Version: 2012.11
Release: 1
Source: https://albinoloverats.net/downloads/%{name}.tar.xz
URL: https://albinoloverats.net/projects/%{name}
License: GPL
BuildRoot: /var/tmp/%{name}
Group: Applications/File
Requires: libgcrypt, gtk3, libcurl, xz

%description
encrypt is a simple encryption application which is suitable for any 
modern OS. It uses the GTK to provide a graphical user interface, yet
is equally usable from the command line.
 
%prep
%setup -q

%build
make -f Makefile all OS_OPTS=-DFEDORA_PATH_HACK

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/{bin,share/{encrypt,applications,man/man1,pixmaps,bash-completion/completions,zsh/functions/Completion/Unix}} # ,share/locale/de/LC_MESSAGES}
make install PREFIX=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/usr/bin/encrypt
/usr/bin/decrypt
/usr/share/encrypt/encrypt.glade
/usr/share/applications/encrypt.desktop
/usr/share/man/man1/encrypt.1a.gz
/usr/share/pixmaps/encrypt.svg
/usr/share/pixmaps/encrypt_button.svg
#/usr/share/file/magic/encrypt
/usr/share/bash-completion/completions/encrypt
/usr/share/zsh/functions/Completion/Unix/_encrypt
#/usr/share/locale/de/LC_MESSAGES/encrypt.mo
