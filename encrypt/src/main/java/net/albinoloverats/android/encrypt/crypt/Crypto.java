/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.crypt;

import gnu.crypto.hash.IMessageDigest;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import net.albinoloverats.android.encrypt.misc.Convert;

public abstract class Crypto extends Thread implements Runnable
{
    protected static final long[] HEADER = { 0x3697de5d96fca0faL, 0xc845c2fa95e2f52dL, Version.CURRENT.magicNumber };

    protected static final int BLOCK_SIZE = 1024;

    protected InputStream source;
    protected OutputStream output;

    protected String path;
    protected String cipher;
    protected String hash;
    protected String mode;
    protected byte[] key;

    protected boolean raw = false;

    public Status status = Status.INIT;
    public final Progress current = new Progress();
    public final Progress total = new Progress();

    protected int blockSize;
    protected boolean compressed = false;
    protected boolean directory = false;
    protected boolean follow_links = false;

    protected Version version = Version.CURRENT;

    protected IMessageDigest checksum;

    @Override
    public void run()
    {
        try
        {
            process();
        }
        catch (final CryptoProcessException e)
        {
            status = e.code;
        }
    }

    abstract protected void process() throws CryptoProcessException;

    public static boolean fileEncrypted(final String path)
    {
        final File f = new File(path);
        if (f.isDirectory())
            return false;

        FileInputStream in = null;
        try
        {
            in = new FileInputStream(f);
            final byte[] header = new byte[Long.SIZE / Byte.SIZE];
            for (int i = 0; i < 1; i++)
            {
                int err = in.read(header, 0, header.length);
                if (err < 0 || Convert.longFromBytes(header) != HEADER[i])
                    return false;
            }
            return true;
        }
        catch (final IOException ignored)
        {
            return false; // either the file doesn't exists or we can't read it for decrypting
        }
        finally
        {
            closeIgnoreException(in);
        }
    }

    public void setKey(final Object k) throws CryptoProcessException
    {
        if (k instanceof File)
        {
            FileInputStream f = null;
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            try
            {
                File file = (File)k;
                f = new FileInputStream(file);
                key = new byte[(int)file.length()];
                f.read(key);
            }
            catch (final IOException e)
            {
                throw new CryptoProcessException(Status.FAILED_KEY, e);
            }
            finally
            {
                closeIgnoreException(f);
                closeIgnoreException(b);
            }
        }
        else if (k instanceof byte[])
            key = (byte[])k;
        else
            throw new CryptoProcessException(Status.FAILED_KEY);
    }

    protected static void closeIgnoreException(final Closeable c)
    {
        try
        {
            if (c != null)
                c.close();
        }
        catch (final IOException ignored)
        {
            ;
        }
    }
}
