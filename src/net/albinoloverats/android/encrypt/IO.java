/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2012, albinoloverats ~ Software Development
 * email: encrypt@albinoloverats.net
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package net.albinoloverats.android.encrypt;

import gnu.crypto.mode.IMode;
import gnu.crypto.util.PRNG;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class IO
{
    public boolean compress = false;
    private byte[] stream = null;
    private int block = 0;
    private int[] offset = { 0, 0, 0 };

    public IO()
    {
        stream = null;
        block = 0;
        offset = new int[3];
    }

    public void write(final FileOutputStream out, final byte[] bytes, final IMode cipher) throws IOException
    {
        if (compress)
            compressedWrite(out, bytes, cipher);
        else
            encryptedWrite(out, bytes, cipher);
    }

    public void read(final FileInputStream in, final byte[] bytes, final IMode cipher) throws IOException
    {
        if (compress)
            compressedRead(in, bytes, cipher);
        else
            encryptedRead(in, bytes, cipher);
    }

    private void compressedWrite(final FileOutputStream out, final byte[] bytes, final IMode cipher) throws IOException
    {
        // TODO
        encryptedWrite(out, bytes, cipher);
    }

    public void compressedRead(final FileInputStream in, final byte[] bytes, final IMode cipher) throws IOException
    {
        // TODO
        encryptedRead(in, bytes, cipher);
    }

    private void encryptedWrite(final FileOutputStream out, final byte[] bytes, final IMode cipher) throws IOException
    {
        if (block == 0)
            block = cipher.defaultBlockSize();
        if (stream == null)
            stream = new byte[block];
        final int[] remainder = { bytes != null ? bytes.length : 0, block - offset[0] };
        if (bytes == null)
        {
            final byte[] x = new byte[remainder[1]];
            PRNG.nextBytes(x);
            System.arraycopy(x, 0, stream, offset[0], remainder[1]);
            final byte[] eBytes = new byte[block];
            cipher.update(stream, 0, eBytes, 0);
            out.write(eBytes);
            block = 0;
            stream = null;
            offset = new int[3];
            out.flush();
            return;
        }
        offset[1] = 0;
        while (remainder[0] > 0)
        {
            if (remainder[0] < remainder[1])
            {
                System.arraycopy(bytes, offset[1], stream, offset[0], remainder[0]);
                offset[0] += remainder[0];
                return;
            }
            System.arraycopy(bytes, offset[1], stream, offset[0], remainder[1]);
            final byte[] eBytes = new byte[block];
            cipher.update(stream, 0, eBytes, 0);
            out.write(eBytes);
            offset[0] = 0;
            stream = new byte[block];
            offset[1] += remainder[1];
            remainder[0] -= remainder[1];
            remainder[1] = block - offset[0];
        }
        return;
    }

    private void encryptedRead(final FileInputStream in, final byte[] bytes, final IMode cipher) throws IOException
    {
        if (block == 0)
            block = cipher.defaultBlockSize();
        if (stream == null)
            stream = new byte[block];
        offset[1] = bytes.length;
        offset[2] = 0;
        while (true)
        {
            if (offset[0] >= offset[1])
            {
                System.arraycopy(stream, 0, bytes, offset[2], offset[1]);
                offset[0] -= offset[1];
                final byte[] x = new byte[block];
                System.arraycopy(stream, offset[1], x, 0, offset[0]);
                stream = new byte[block];
                System.arraycopy(x, 0, stream, 0, offset[0]);
                return;
            }
            System.arraycopy(stream, 0, bytes, offset[2], offset[0]);
            offset[2] += offset[0];
            offset[1] -= offset[0];
            offset[0] = 0;
            final byte[] eBytes = new byte[block];
            in.read(eBytes);
            cipher.update(eBytes, 0, stream, 0);
            offset[0] = block;
        }
    }
}
