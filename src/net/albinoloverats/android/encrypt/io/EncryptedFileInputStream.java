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

package net.albinoloverats.android.encrypt.io;

import gnu.crypto.mode.IMode;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;

public class EncryptedFileInputStream extends FileInputStream
{
    private final FileInputStream stream;
    private IMode cipher;
    private byte[] buffer = null;
    private int block = 0;
    private final int[] offset = { 0, 0, 0 };

    public EncryptedFileInputStream(final File file) throws FileNotFoundException
    {
        super(file);
        stream = new FileInputStream(file);
    }

    public void setCipher(final IMode cipher)
    {
        this.cipher = cipher;
    }

    @Override
    public int available()
    {
        return offset[0];
    }

    @Override
    public void close() throws IOException
    {
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
    public int read() throws IOException
    {
        final byte[] b = new byte[1];
        read(b);
        return b[0];
    }

    @Override
    public int read(final byte[] bytes) throws IOException
    {
        if (cipher == null)
            return stream.read(bytes);
        if (block == 0)
            block = cipher.defaultBlockSize();
        if (buffer == null)
            buffer = new byte[block];
        offset[1] = bytes.length;
        offset[2] = 0;
        while (true)
        {
            if (offset[0] >= offset[1])
            {
                System.arraycopy(buffer, 0, bytes, offset[2], offset[1]);
                offset[0] -= offset[1];
                final byte[] x = new byte[block];
                System.arraycopy(buffer, offset[1], x, 0, offset[0]);
                buffer = new byte[block];
                System.arraycopy(x, 0, buffer, 0, offset[0]);
                return offset[0];
            }
            System.arraycopy(buffer, 0, bytes, offset[2], offset[0]);
            offset[2] += offset[0];
            offset[1] -= offset[0];
            offset[0] = 0;
            final byte[] eBytes = new byte[block];
            stream.read(eBytes);
            cipher.update(eBytes, 0, buffer, 0);
            offset[0] = block;
        }
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException
    {
        final byte[] bytes = new byte[len];
        final int x = read(bytes);
        System.arraycopy(bytes, 0, b, off, len);
        return x;
    }

    @Override
    public long skip(final long n) throws IOException
    {
        if (n < 0)
            throw new IOException();
        final byte[] bytes = new byte[(int)n];
        return read(bytes);
    }
}
