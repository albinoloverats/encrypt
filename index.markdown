encrypt is a small application which has been designed, from the beginning (all three of them so far), to be as simple to use as is practical. The idea is small and simple, yet with encryption that aims to be a strong as possible, while also giving the user the choice about how their data is secured.

It is mostly written in C, and uses the [GTK][] for the GUI (version 3.0 or later), to help increase the portability and usefulness across many different operating systems. All of the cryptographic functions are provided by [libgcrypt][]; this increases the number of available algorithms for the end user, and also ensures that the implementations are correct and (largely) free of (serious) bugs :-)

Not only do we have an Android version, but we also now have a native release for Mac OS X! (Of course if you would prefer, you can still build an X11 version using Homebrew and following the typical *nix instructions in the documentation.)

Currently we provide 64 bit binary packages&mdash;with GUI&mdash;for Arch, Debian, Fedora, Slackware, FreeBSD, Solaris 11, Apple's OS X, as well as Microsoft Windows. The DEB package should be compatible with the latest version of Ubuntu, and the RPM is _(mostly)_ compatible with SUSE (it might complain that it cannot satisfy the cURL dependency but this can be ignored; you just won't be prompted when a new version of encrypt is available). The Windows package has been built and tested on Windows 11. We're still working on an ebuild file for Gentoo, but it does compile and run without any issues provided you're willing to do some manual dependency management.

It's this level of portability and simplicity which we hope will make encrypt more useful to people who use different operating systems in different situations: home, office, on the go, etc. as it uses the same algorithms and interface. <span style="color:#dc143c;">Be aware that the Whirlpool algorithm is different on desktops versus Android.</span>

NB: It has been noted that some characters, when used in the password, aren't completely cross-platform; for instance the character £ doesn't play well on Android devices.

Binary packages, and GPG signatures, for version 2024.01 are available below (as well as at [Sourceforge]):

|OS|Package|GPG Signature|Screenshots|
|-|-|-|-|
|[Arch Linux]|[pkg][ap]|[Signature][ag]|[GTK+3 / Xfce][as]|
|[Debian]|[deb][dp]|[Signature][dg]|_See above_|
|[Fedora]|[rpm][fp]|[Signature][fg]|_See above_|
|[Slackware]|[tgz][kp]|[Signature][kg]|_See above_|
|[FreeBSD]|[txz][bp]|[Signature][bg]|_See above_|
|[Solaris]|[pkg][sp]|[Signature][sg]|_See above_|
|[Windows]|[exe][wp]|[Signature][wg]|[GTK+3 / Windows][ws]|
|[OS X]|[pkg¹][xp]|[Signature][xg]|[Native OS X][xs]|
|[Android]|[Paid][mp]/[Free][gp]|[Signature (Free)][gg]|[Nougat][ms]|
|Desktop Source|[.tar.xz][rp] or [.zip][rz]|[Signature][rg] or [Zip Sig][ry]|_See above_|
|Android Source|[.tar.xz][qp] or [.zip][qz]|[Signature][qg] or [Zip Sig][qy]|_See above_|

.

A demo of using the CLI can be found over on [asciinema](https://asciinema.org/a/450022), whereas a GUI demo can be found within the [pixmaps](/src/encrypt/pixmaps/screencast_linux.mp4) directory as well as on [YouTube](https://youtu.be/4au0MWCjIzI).

¹ At the moment, the OS X app isn't signed by Apple and as such you will be presented with a warning about encrypt being untrusted. This can be overridden in the security settings.

[GTK]: http://www.gtk.org
[libgcrypt]: http://www.gnu.org/software/libgcrypt/
[Android]: http://www.android.com
[SourceForge.net]: http://sourceforge.net
[Homebrew]: http://mxcl.github.com/homebrew/
[Xcode]: https://developer.apple.com/xcode/
[Sourceforge]: https://sourceforge.net/projects/encrypt/

[Arch Linux]: http://www.archlinux.org
[ap]: /downloads/encrypt/2024.01/encrypt-2024.01-1-x86_64.pkg.tar.zst
[ag]: /downloads/encrypt/2024.01/encrypt-2024.01-1-x86_64.pkg.tar.zst.asc
[as]: /src/encrypt/pixmaps/screenshot_linux_idle.png

[Debian]: http://www.debian.org
[dp]: /downloads/encrypt/2024.01/encrypt_2024.01-1_amd64.deb
[dg]: /downloads/encrypt/2024.01/encrypt_2024.01-1_amd64.deb.asc

[Fedora]: http://fedoraproject.org
[fp]: /downloads/encrypt/2024.01/encrypt-2024.01-1.x86_64.rpm
[fg]: /downloads/encrypt/2024.01/encrypt-2024.01-1.x86_64.rpm.asc

[Slackware]: http://http://www.slackware.com
[kp]: /downloads/encrypt/2024.01/encrypt-2024.01-x86_64-1aa.tgz
[kg]: /downloads/encrypt/2024.01/encrypt-2024.01-x86_64-1aa.tgz.asc

[FreeBSD]: https://www.freebsd.org
[bp]: /downloads/encrypt/2024.01/encrypt-2024.01.pkg
[bg]: /downloads/encrypt/2024.01/encrypt-2024.01.pkg.asc

[Solaris]: https://www.oracle.com/solaris/solaris11/
[sp]: /downloads/encrypt/2024.01/encrypt-2024.01-i386.pkg
[sg]: /downloads/encrypt/2024.01/encrypt-2024.01-i386.pkg.asc

[Windows]: https://www.microsoft.com
[wp]: /downloads/encrypt/2024.01/encrypt-2024.01-install.exe
[wg]: /downloads/encrypt/2024.01/encrypt-2024.01-install.exe.asc
[ws]: /src/encrypt/pixmaps/screenshot_windows_idle.png

[mp]: https://market.android.com/details?id=net.albinoloverats.android.encrypt
[ms]: /src/encrypt/pixmaps/screenshot_android_idle.png
[gp]: /downloads/encrypt/2024.01/encrypt-2024.01-free.apk
[gg]: /downloads/encrypt/2024.01/encrypt-2024.01-free.apk.asc

[OS X]: https://www.apple.com
[xp]: /downloads/encrypt/2024.01/encrypt-2024.01-install.pkg
[xg]: /downloads/encrypt/2024.01/encrypt-2024.01-install.pkg.asc
[xs]: /src/encrypt/pixmaps/screenshot_macosx_idle.png

[rp]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.tar.xz
[rg]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.tar.xz.asc
[rz]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.zip
[ry]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.zip.asc

[qp]: /downloads/encrypt/2024.01/encrypt-2024.01-android-src.tar.xz
[qg]: /downloads/encrypt/2024.01/encrypt-2024.01-android-src.tar.xz.asc
[qz]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.zip
[qy]: /downloads/encrypt/2024.01/encrypt-2024.01-desktop-src.zip.asc

[qr]: https://qrcode.kaywa.com/img.php?s=2&d=https%3A%2F%2Fmarket.android.com%2Fdetails%3Fid%3Dnet.albinoloverats.android.encrypt

*[GTK]: Gimp Tool Kit
*[GUI]: Graphical User Interface
*[GNU]: GNU's Not Unix
*[GPG]: GNU Privacy Guard
