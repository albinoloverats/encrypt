package gnu.crypto.mac;  // -*- c-basic-offset: 3 -*-

// ---------------------------------------------------------------------------
// $Id: MacInputStream.java,v 1.2 2005/10/06 04:24:16 rsdio Exp $
//
// Copyright (C) 2003 Free Software Foundation, Inc.
//
// This file is part of GNU Crypto.
//
// GNU Crypto is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2, or (at your option)
// any later version.
//
// GNU Crypto is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; see the file COPYING.  If not, write to the
//
//    Free Software Foundation Inc.,
//    51 Franklin Street, Fifth Floor,
//    Boston, MA 02110-1301
//    USA
//
// Linking this library statically or dynamically with other modules is
// making a combined work based on this library.  Thus, the terms and
// conditions of the GNU General Public License cover the whole
// combination.
//
// As a special exception, the copyright holders of this library give
// you permission to link this library with independent modules to
// produce an executable, regardless of the license terms of these
// independent modules, and to copy and distribute the resulting
// executable under terms of your choice, provided that you also meet,
// for each linked independent module, the terms and conditions of the
// license of that module.  An independent module is a module which is
// not derived from or based on this library.  If you modify this
// library, you may extend this exception to your version of the
// library, but you are not obligated to do so.  If you do not wish to
// do so, delete this exception statement from your version.
//
// ---------------------------------------------------------------------------

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * A filtering input stream that computes a MAC (message authentication code)
 * over all data read from the stream.
 *
 * @version $Revision: 1.2 $
 */
public class MacInputStream extends FilterInputStream {

   // Field.
   // ------------------------------------------------------------------------

   /**
    * The digesting state. The MAC is updated only if this flag is true.
    */
   private boolean digesting;

   /**
    * The MAC being updated.
    */
   private IMac mac;

   // Constructor.
   // ------------------------------------------------------------------------

   /**
    * Creates a new MacInputStream. The stream is initially set to digest
    * data written, the <i>mac</i> argument must have already been initialized,
    * and the <i>mac</i> argument is <b>not</b> cloned.
    *
    * @param in The underlying input stream.
    * @param mac The mac instance to use.
    */
   public MacInputStream(InputStream in, IMac mac) {
      super(in);
      if (mac == null)
         throw new NullPointerException();
      this.mac = mac;
      digesting = true;
   }

   // Instance methods.
   // ------------------------------------------------------------------------

   /**
    * Returns the MAC this stream is updating.
    *
    * @return The MAC.
    */
   public IMac getMac() {
      return mac;
   }

   /**
    * Sets the MAC this stream is updating, which must have already been
    * initialized. The argument is not cloned by this method.
    *
    * @param mac The new MAC.
    * @throws NullPointerException If the argument is null.
    */
   public void setMac(IMac mac) {
      if (mac == null)
         throw new NullPointerException();
      this.mac = mac;
   }

   /**
    * Turns the digesting state on or off. When off, the MAC will not be
    * updated when data is written to the stream.
    *
    * @param flag The new digesting state.
    */
   public void on(boolean flag) {
      digesting = flag;
   }

   public int read() throws IOException {
      int i = in.read();
      if (digesting && i != -1)
         mac.update((byte) i);
      return i;
   }

   public int read(byte[] buf, int off, int len) throws IOException {
      int i = in.read(buf, off, len);
      if (digesting && i != -1)
         mac.update(buf, off, i);
      return i;
   }
}
