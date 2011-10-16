Summary: A simple, X-platform, encryption application
Name: encrypt
Version: 201110
Release: 1
Source: https://albinoloverats.net/downloads/%{name}-%{version}.tar.bz2
URL: https://albinoloverats.net/projects/%{name}
License: GPL
BuildRoot: /var/tmp/%{name}
Group: Applications/File

%description
encrypt is a simple encryption application which is suitable for any 
modern OS. It uses the GTK to provide a graphical user interface, yet
is equally usable from the command line.
 
%prep
%setup -q

%build
make all OS_OPTS=-DFEDORA_PATH_HACK

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/{bin,share/{encrypt,man/man1,applications,pixmaps}} # ,share/locale/de/LC_MESSAGES}
make install PREFIX=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/usr/bin/encrypt
/usr/share/encrypt/encrypt.glade
/usr/share/man/man1/encrypt.1a.gz
/usr/share/applications/encrypt.desktop
/usr/share/pixmaps/encrypt.svg
/usr/share/pixmaps/encrypt.png
#/usr/share/locale/de/LC_MESSAGES/encrypt.mo
