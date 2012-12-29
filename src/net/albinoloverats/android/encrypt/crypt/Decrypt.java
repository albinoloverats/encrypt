/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2013, albinoloverats ~ Software Development
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.albinoloverats.android.encrypt.io.EncryptedFileInputStream;
import net.albinoloverats.android.encrypt.misc.Convert;

import org.tukaani.xz.XZInputStream;

public class Decrypt extends Crypto
{
    public Decrypt(final String source, final String output, final byte[] key) throws Exception
    {
        super();

        try
        {
            this.source = new EncryptedFileInputStream(new File(source));
            final File out = new File(output);
            if (out.exists() && out.isDirectory())
            {
                directory = true;
                path = output;
            }
            else if (out.exists())
                this.output = new FileOutputStream(output);
            else
                path = output;
        }
        catch (final FileNotFoundException e)
        {
            throw new Exception(Status.FAILED_IO, e);
        }

        if (key == null)
            throw new Exception(Status.FAILED_INIT);
        else
            this.key = key;
    }

    @Override
    protected void process() throws Exception
    {
        try
        {
            status = Status.RUNNING;

            final long version = readVersion();
            checksum = ((EncryptedFileInputStream)source).encryptionInit(cipher, hash, key,
                    version == HEADER_VERSION_201108 ||
                    version == HEADER_VERSION_201110);

            boolean skipRandom = false;
            if (version == HEADER_VERSION_201108 ||
                version == HEADER_VERSION_201110 ||
                version == HEADER_VERSION_201211)
                skipRandom = true;

            if (!skipRandom)
                skipRandomData();
            readVerificationSum();
            skipRandomData();
            readMetadata();
            if (!skipRandom)
                skipRandomData();

            source = compressed ? new XZInputStream(source) : source;

            checksum.reset();

            if (directory)
                decryptDirectory(path);
            else
            {
                current.size = total.size;
                total.size = 1;
                if (blocksize > 0)
                    decryptStream();
                else
                    decryptFile();
            }

            final byte[] check = new byte[checksum.hashSize()];
            source.read(check);
            if (!Arrays.equals(check, checksum.digest()))
                throw new Exception(Status.FAILED_CHECKSUM);

            status = Status.SUCCESS;
        }
        catch (final Exception e)
        {
            status = e.code;
            throw e;
        }
        catch (final NoSuchAlgorithmException e)
        {
            status = Status.FAILED_UNKNOWN_ALGORITH;
            throw new Exception(Status.FAILED_UNKNOWN_ALGORITH, e);
        }
        catch (final InvalidKeyException e)
        {
            status = Status.FAILED_OTHER;
            throw new Exception(Status.FAILED_OTHER, e);
        }
        catch (final IOException e)
        {
            status = Status.FAILED_IO;
            throw new Exception(Status.FAILED_IO, e);
        }
        finally
        {
            try
            {
                if (output != null)
                    output.close();
                source.close();
            }
            catch (final IOException e)
            {
                ;
            }
        }
    }

    private long readVersion() throws Exception, IOException
    {
        final byte[] header = new byte[Long.SIZE / Byte.SIZE];
        for (int i = 0; i < 3; i++)
            source.read(header, 0, header.length);

        final byte[] b = new byte[source.read()];
        source.read(b);

        final String a = new String(b);
        cipher = a.substring(0, a.indexOf('/'));
        hash = a.substring(a.indexOf('/') + 1);

        final long version = Convert.longFromBytes(header);
        if (version == HEADER_VERSION_201108 ||
            version == HEADER_VERSION_201110 ||
            version == HEADER_VERSION_201211 ||
            version == HEADER_VERSION_LATEST)
            return version;
        else
            throw new Exception(Status.FAILED_UNKNOWN_VERSION);
    }

    private void readVerificationSum() throws Exception, IOException
    {
        final byte buffer[] = new byte[Long.SIZE / Byte.SIZE];
        source.read(buffer);
        final long x = Convert.longFromBytes(buffer);
        source.read(buffer);
        final long y = Convert.longFromBytes(buffer);
        source.read(buffer);
        final long z = Convert.longFromBytes(buffer);
        if ((x ^ y) != z)
            throw new Exception(Status.FAILED_DECRYPTION);
        return;
    }

    private void readMetadata() throws Exception, IOException
    {
        final int c = source.read();
        for (int i = 0; i < c; i++)
        {
            final Tag tag = Tag.fromValue(source.read());
            final byte[] l = new byte[Short.SIZE / Byte.SIZE];
            source.read(l);
            final int length = Convert.shortFromBytes(l);
            final byte[] v = new byte[length];
            source.read(v);
            switch (tag)
            {
                case SIZE:
                    total.size = Convert.longFromBytes(v);
                    break;
                case BLOCKED:
                    blocksize = (int)Convert.longFromBytes(v);
                    break;
                case COMPRESSED:
                    compressed = Convert.booleanFromBytes(v);
                    break;
                case DIRECTORY:
                    {
                        directory = Convert.booleanFromBytes(v);
                        final File f = new File(path);
                        if (directory)
                        {
                            if (!f.exists())
                                f.mkdirs();
                            else if (!f.isDirectory())
                                throw new Exception(Status.FAILED_OUTPUT_MISMATCH);
                        }
                        else
                        {
                            if (!f.exists())
                                output = new FileOutputStream(f);
                            else if (!f.isFile())
                                throw new Exception(Status.FAILED_OUTPUT_MISMATCH);
                        }
                    }
                    break;
            }
        }
        return;
    }

    private void skipRandomData() throws IOException
    {
        final byte[] b = new byte[source.read()];
        source.read(b);
        return;
    }

    private void decryptDirectory(final String dir) throws Exception, IOException
    {
        for (total.offset = 0; total.offset < total.size; total.offset++)
        {
            if (status != Status.RUNNING)
                break;

            final FileType t = FileType.fromID(source.read());
            byte[] b = new byte[Long.SIZE / Byte.SIZE];
            source.read(b);
            final long l = Convert.longFromBytes(b);
            b = new byte[(int)l];
            source.read(b);
            final String nm = dir + File.separator + new String(b);
            switch (t)
            {
                case DIRECTORY:
                    new File(nm).mkdirs();
                    break;
                case REGULAR:
                    current.offset = 0;
                    b = new byte[Long.SIZE / Byte.SIZE];
                    source.read(b);
                    current.size = Convert.longFromBytes(b);
                    output = new FileOutputStream(nm);
                    decryptFile();
                    current.offset = current.size;
                    output.close();
                    output = null;
                    break;
            }
        }
        return;
    }

    private void decryptStream() throws IOException
    {
        boolean b = true;
        byte[] buffer = new byte[blocksize];
        while (b)
        {
            if (status == Status.CANCELLED)
                break;
            b = source.read() == 1;
            source.read(buffer);
            int r = blocksize;
            if (!b)
            {
                final byte[] l = new byte[Long.SIZE / Byte.SIZE];
                source.read(l);
                r = (int)Convert.longFromBytes(l);
                final byte[] tmp = new byte[r];
                System.arraycopy(buffer, 0, tmp, 0, r);
                buffer = new byte[r];
                System.arraycopy(tmp, 0, buffer, 0, r);
            }
            checksum.update(buffer, 0, r);
            output.write(buffer);
            current.offset += r;
        }
        return;
    }

    private void decryptFile() throws IOException
    {
        final byte[] buffer = new byte[BLOCK_SIZE];
        for (current.offset = 0; current.offset < current.size; current.offset += BLOCK_SIZE)
        {
            if (status == Status.CANCELLED)
                break;
            int j = BLOCK_SIZE;
            if (current.offset + BLOCK_SIZE > current.size)
                j = (int)(BLOCK_SIZE - (current.offset + BLOCK_SIZE - current.size));
            final int r = source.read(buffer, 0, j);
            checksum.update(buffer, 0, r);
            output.write(buffer, 0, r);
        }
        return;
    }
}
