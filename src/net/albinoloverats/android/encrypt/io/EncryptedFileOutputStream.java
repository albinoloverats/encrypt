/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.io;

import gnu.crypto.mode.IMode;
import gnu.crypto.util.PRNG;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;

import net.albinoloverats.android.encrypt.utils.Convert;

public class EncryptedFileOutputStream extends FileOutputStream
{
    private final FileOutputStream stream;
    private IMode cipher;
    private byte[] buffer = null;
    private int block = 0;
    private int[] offset = { 0, 0, 0 };

    public EncryptedFileOutputStream(final File file) throws FileNotFoundException
    {
        super(file);
        stream = new FileOutputStream(file);
    }

    public void setCipher(final IMode cipher)
    {
        this.cipher = cipher;
    }

    @Override
    public void close() throws IOException
    {
        final int[] remainder = { 0, block - offset[0] };
        final byte[] x = new byte[remainder[1]];
        PRNG.nextBytes(x);
        System.arraycopy(x, 0, buffer, offset[0], remainder[1]);
        final byte[] eBytes = new byte[block];
        cipher.update(buffer, 0, eBytes, 0);
        stream.write(eBytes);
        block = 0;
        buffer = null;
        offset = new int[3];
        stream.flush();
        stream.close();
    }

    @Override
    protected void finalize() throws IOException
    {
        close();
    }

    @Override
    public FileChannel getChannel()
    {
        return stream.getChannel();
    }

    @Override
    public void write(final byte[] bytes) throws IOException
    {
        if (cipher == null)
        {
            stream.write(bytes);
            return;
        }
        if (block == 0)
            block = cipher.defaultBlockSize();
        if (buffer == null)
            buffer = new byte[block];
        final int[] remainder = { bytes.length, block - offset[0] };
        offset[1] = 0;
        while (remainder[0] > 0)
        {
            if (remainder[0] < remainder[1])
            {
                System.arraycopy(bytes, offset[1], buffer, offset[0], remainder[0]);
                offset[0] += remainder[0];
                return;
            }
            System.arraycopy(bytes, offset[1], buffer, offset[0], remainder[1]);
            final byte[] eBytes = new byte[block];
            cipher.update(buffer, 0, eBytes, 0);
            stream.write(eBytes);
            offset[0] = 0;
            buffer = new byte[block];
            offset[1] += remainder[1];
            remainder[0] -= remainder[1];
            remainder[1] = block - offset[0];
        }
        return;
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException
    {
        final byte[] bytes = new byte[len];
        System.arraycopy(b, off, bytes, 0, len);
        write(bytes);
    }

    @Override
    public void write(final int b) throws IOException
    {
        write(Convert.toBytes((byte)(b & 0x000000FF)));
    }
}
