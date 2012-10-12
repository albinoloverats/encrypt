encrypt - 2012.-1 (pre-release)                           28th Sept 2012

A few notes before release:
 - Data is now compressed before encryption
   - TODO: Don't compress if the data is already compressed
   - Allow the user to toggle compression via command line argument
   - Update/Check compatibility on Windows/Mac OS X
     - Windows GUI is being a pain in the arse
     - Mac OS X requires Homebrew, GTK, GDK, etc and X11  (a native OS X
       port is in the works)
   - Update build scripts to link to liblzma
   - Add compression support to Android app

The encrypt Development Team


Copyright/Licencing:
  All components of encrypt are freely available under one free software
  licence or another. The cryptographic libraries (glibc and gnu-crypto)
  are both available  under the terms of the GNU General Public License;
  GTK and  GDK are available  under the terms of the  GNU Lesser General
  Public License.  The Android File Dialog is available under the  terms
  of the FreeBSD License.

  The icon  used by  encrypt is a modification  taken  from  the Crystal
  Clear icon set,  which makes  it available  under the terms of the GNU
  Lesser General Public License.

  Copies of all of the above licences should have been distributed along
  with encrypt, in source or binary form.


Prerequisites:
  Desktop implementation:
    - GTK (and all of its requirements: GDK/Cairo/etc)---version 2.24 or
      later---version 3 is recommended (and available on most/some Linux
      and Mac OS X using Homebrew)
    - libgcrypt cryptographic library
    - pthread library

  Android implementation:
    gnu-crypto
    Android File Dialog - http://code.google.com/p/android-file-dialog/


Build/Installation instructions:
  For most,  installing encrypt will pull in all the required libraries,
  either  through your systems  package management system,  or if you're
  on  MS Windows,  the  installer  includes all  the  necessary  runtime
  libraries.  If you  intend to  build from source  you will require the
  development packages too.

  On GNU/Linux Systems:
    Simply:
      $ make -f Makefile
      # make -f Makefile install

    To build with the GTK GUI:
      $ make -f Makefile gui
      $ make -f Makefile install

    Eventually, you may need the following:
      $ make -f Makefile clean
      $ make -f Makefile distclean
      # make -f Makefile uninstall

  On MS Systems:
    It's all done for you  (Using Dev-C++)---if you wish to compile from
    source  yourself,  this shouldn't  be too  much  of a  problem using
    Dev-C++ (just ask if you need help). The NSIS script will then allow
    you to  build the installer  (or you can just  copy the  binaries to
    wherever and go from there).

  On Mac OS X:
    For now you'll need Homebrew: http://mxcl.github.com/homebrew/
    As well as GTK and all of its dependencies (a proper OS X port is in
    the works but will have to fit around the current GUI code; which is
    hardcoded to use GTK).  The build instructions are the same as those
    for GNU/Linux.

  For Android:
    Import the Eclipse/Android project into  Eclipse and build using the
    standard Android development tools.
