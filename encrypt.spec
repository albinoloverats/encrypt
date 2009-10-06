Summary: A simple, X-platform, plugin-based encryption application
Name: encrypt
Version: 200910
Release: 1
Source: https://albinoloverats.net/downloads/%{name}.tar.bz2
URL: https://albinoloverats.net/%{name}
License: GPL
BuildRoot: /var/tmp/%{name}
Group: Applications/File

%description
encrypt is a simple encryption application which is suitable for any 
modern OS. It uses the GTK to provide a graphical user interface, yet
is equally usable from the command line. Plugins allow additional 
algorithms to be chosen by the user at runtime.
 
%prep
%setup -q

%build
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/{bin,lib,man/man1,share/{applications,locale/de/LC_MESSAGES}}
make gui-all PREFIX=%{buildroot}

%install
make install-all PREFIX=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/usr/bin/encrypt
/usr/man/man1/encrypt.1a.gz
/usr/share/applications/encrypt.desktop
/usr/lib/encrypt
/usr/lib/anubis.so
/usr/lib/helloworld.so
/usr/lib/serpent.so
/usr/lib/xtea.so
/usr/share/locale/de/LC_MESSAGES/encrypt.mo
