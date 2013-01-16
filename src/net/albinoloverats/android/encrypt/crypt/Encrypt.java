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

import gnu.crypto.util.PRNG;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import net.albinoloverats.android.encrypt.io.EncryptedFileOutputStream;
import net.albinoloverats.android.encrypt.misc.Convert;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZOutputStream;

public class Encrypt extends Crypto
{
    private String root = "";
    
    public Encrypt(final String source, final String output, final String cipher, final String hash, final byte[] key, final boolean compress) throws Exception
    {
        super();

        try
        {
            final File in = new File(source);
            if (in.isFile())
            {
                total.size = in.length();
                this.source = new FileInputStream(in);
            }
            else if (in.isDirectory())
            {
                directory = true;
                path = source;
            }
            else
                throw new Exception(Status.FAILED_IO);
            this.output = new EncryptedFileOutputStream(new File(output));
        }
        catch (final FileNotFoundException e)
        {
            throw new Exception(Status.FAILED_IO, e);
        }

        this.cipher = cipher;
        this.hash = hash;

        if (key == null)
            throw new Exception(Status.FAILED_INIT);
        else
            this.key = key;

        compressed = compress;
    }

    @Override
    protected void process() throws Exception
    {
        try
        {
            status = Status.RUNNING;

            writeHeader();
            checksum = ((EncryptedFileOutputStream)output).encryptionInit(cipher, hash, key);

            writeRandomData();
            writeVerificationSum();
            writeRandomData();
            writeMetadata();
            writeRandomData();

            final LZMA2Options opts = new LZMA2Options(LZMA2Options.PRESET_DEFAULT);
            opts.setDictSize(LZMA2Options.DICT_SIZE_MIN); // default dictionary size is 8MiB which is too large

            output = compressed ? new XZOutputStream(output, opts) : output;

            checksum.reset();

            if (directory)
            {
                final File d = new File(path);
                root = d.getParent();
                output.write(Convert.toBytes((byte)FileType.DIRECTORY.value));
                output.write(Convert.toBytes((long)d.getName().length()));
                output.write(d.getName().getBytes());
                total.offset = 1;
                encryptDirectory(path);
                total.offset = total.size;
                current.offset = current.size;
            }
            else
            {
                current.size = total.size;
                total.size = 1;
                encryptFile();
                current.offset = current.size;
                total.offset = total.size;
            }

            output.write(checksum.digest());

            writeRandomData();

            status = Status.SUCCESS;
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
                output.close();
                if (source != null)
                    source.close();
            }
            catch (final IOException e)
            {
                ;
            }
        }
    }

    private void writeHeader() throws IOException
    {
        output.write(Convert.toBytes(HEADER[0]));
        output.write(Convert.toBytes(HEADER[1]));
        output.write(Convert.toBytes(HEADER[2]));
        final String algos = cipher + "/" + hash;
        output.write((byte)algos.length());
        output.write(algos.getBytes());
        return;
    }

    private void writeVerificationSum() throws IOException
    {
        final byte buffer[] = new byte[Long.SIZE / Byte.SIZE];
        PRNG.nextBytes(buffer);
        final long x = Convert.longFromBytes(buffer);
        PRNG.nextBytes(buffer);
        final long y = Convert.longFromBytes(buffer);
        output.write(Convert.toBytes(x));
        output.write(Convert.toBytes(y));
        output.write(Convert.toBytes(x ^ y));
        return;
    }

    private void writeMetadata() throws IOException
    {
        output.write(Convert.toBytes((byte)3));

        if (directory)
            total.size = countEntries(path) + 1;

        output.write(Convert.toBytes((byte)Tag.SIZE.value));
        output.write(Convert.toBytes((short)(Long.SIZE / Byte.SIZE)));
        output.write(Convert.toBytes(total.size));

        output.write(Convert.toBytes((byte)Tag.COMPRESSED.value));
        output.write(Convert.toBytes((short)(Byte.SIZE / Byte.SIZE)));
        output.write(Convert.toBytes(compressed));

        output.write(Convert.toBytes((byte)Tag.DIRECTORY.value));
        output.write(Convert.toBytes((short)(Byte.SIZE / Byte.SIZE)));
        output.write(Convert.toBytes(directory));

        return;
    }

    private void writeRandomData() throws IOException
    {
        byte[] buffer = new byte[Short.SIZE / Byte.SIZE];
        PRNG.nextBytes(buffer);
        final short sr = (short)(Convert.shortFromBytes(buffer) & 0x00FF);
        buffer = new byte[sr];
        PRNG.nextBytes(buffer);
        output.write(Convert.toBytes((byte)sr));
        output.write(buffer);
        return;
    }

    private int countEntries(final String dir) throws IOException
    {
        int c = 0;
        for (final File file : new File(dir).listFiles())
            if (file.isDirectory())
                c += countEntries(dir + File.separator + file.getName());
            else if (file.isFile())
                c++;
        return c;
    }

    private void encryptDirectory(final String dir) throws IOException
    {
        for (final File file : new File(dir).listFiles())
        {
            if (status != Status.RUNNING)
                break;

            if (!file.isDirectory() && !file.isFile())
                continue;

            output.write(Convert.toBytes((byte)(file.isDirectory() ? FileType.DIRECTORY.value : FileType.REGULAR.value)));
            final String name = dir + File.separator + file.getName();
            final String nm = name.substring(root.length() + 1);
            output.write(Convert.toBytes((long)nm.length()));
            output.write(nm.getBytes());

            if (file.isDirectory())
                encryptDirectory(name);
            else
            {
                source = new FileInputStream(file);
                current.offset = 0;
                current.size = file.length();
                output.write(Convert.toBytes(current.size));
                encryptFile();
                current.offset = current.size;
                source.close();
                source = null;
            }
            total.offset++;
        }
        return;
    }

    private void encryptFile() throws IOException
    {
        final byte[] buffer = new byte[BLOCK_SIZE];
        for (current.offset = 0; current.offset < current.size && status == Status.RUNNING; current.offset += BLOCK_SIZE)
        {
            final int r = source.read(buffer, 0, BLOCK_SIZE);
            checksum.update(buffer, 0, r);
            output.write(buffer, 0, r);
        }
        return;
    }

}
