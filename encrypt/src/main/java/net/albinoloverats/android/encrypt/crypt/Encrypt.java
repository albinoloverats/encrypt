/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2015, albinoloverats ~ Software Development
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

import android.content.Intent;

import gnu.crypto.mode.ModeFactory;
import gnu.crypto.util.PRNG;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
/*
 * If, and when, Android supports Java7 NIO:
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
 */
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import net.albinoloverats.android.encrypt.io.EncryptedFileOutputStream;
import net.albinoloverats.android.encrypt.misc.Convert;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZFormatException;
import org.tukaani.xz.XZOutputStream;

public class Encrypt extends Crypto
{
    private String root = "";
    /*
     * If, and when, Android supports Java7 NIO:
    private boolean follow = false;
    private Map<Long, Path> inodes = new HashMap<Long, Path>();
     */

    @Override
    public int onStartCommand(final Intent intent, final int flags, final int startId)
    {
        final String source = intent.getStringExtra("source");
        final String output = intent.getStringExtra("output");
        cipher       = intent.getStringExtra("cipher");
        hash         = intent.getStringExtra("hash");
        mode         = intent.getStringExtra("mode");
        key          = intent.getByteArrayExtra("key");
        raw          = intent.getBooleanExtra("raw", raw);
        compressed   = intent.getBooleanExtra("compress", compressed);
        follow_links = intent.getBooleanExtra("follow", follow_links);
        version      = Version.parseMagicNumber(intent.getLongExtra("version", Version.CURRENT.magicNumber), Version.CURRENT);

        try
        {
            final File in = new File(source);
            name = in.getName();
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
                status = Status.FAILED_IO;
            final File out = new File(output);
            if (out.isFile() || !out.exists())
                this.output = new EncryptedFileOutputStream(out);
            else if (out.isDirectory())
                this.output = new EncryptedFileOutputStream(new File(out.getAbsolutePath() + File.separatorChar + name + ".X"));
            else
                status = Status.FAILED_IO;
        }
        catch (final FileNotFoundException e)
        {
            status = Status.FAILED_IO;
        }

        if (raw)
            version = Version.CURRENT;

        switch (this.version)
        {
            // see src/encrypt.c for information/comments
            case _201108:
            case _201110:
                version = Version._201108;
                compressed = false;
            case _201211:
                if (directory)
                    status = Status.FAILURE_COMPATIBILITY;
                if (!compressed)
                    version = Version._201108;
                break;
            case _201302:
                follow_links = false;
            case _201311:
                mode = ModeFactory.CBC_MODE;
                break;
            case _201406:
            case _201501:
            case CURRENT:
                break;
        }

        intent.putExtra("encrypting", true);
        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    protected void process() throws CryptoProcessException
    {
        try
        {
            status = Status.RUNNING;

            if (!raw)
                writeHeader();

            boolean extraRandom = true;
            XIV ivType = XIV.RANDOM;
            if (version.compareTo(Version._201211) <= 0)
            {
                ivType = XIV.SIMPLE;
                extraRandom = false;
            }
            if (version.compareTo(Version._201110) <= 0)
                ivType = XIV.BROKEN;

            checksum = ((EncryptedFileOutputStream)output).encryptionInit(cipher, hash, mode, key, ivType);

            if (!raw)
            {
                if (extraRandom)
                    writeRandomData();
                writeVerificationSum();
                writeRandomData();
            }
            writeMetadata();

            if (extraRandom && !raw)
                writeRandomData();

            final LZMA2Options opts = new LZMA2Options(LZMA2Options.PRESET_MIN); // minimum compression
            opts.setDictSize(LZMA2Options.DICT_SIZE_MIN); // default dictionary size is 8MiB which is too large (on older devices)

//            output = compressed ? new XZOutputStream(output, opts) : output;

            checksum.reset();

            if (directory)
            {
                final File d = new File(path);
                root = d.getParent();
                hashAndWrite(Convert.toBytes((byte)FileType.DIRECTORY.value));
                hashAndWrite(Convert.toBytes((long)d.getName().length()));
                hashAndWrite(d.getName().getBytes());
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

            if (!raw)
            {
                output.write(checksum.digest());
                writeRandomData();
            }

            status = Status.SUCCESS;
        }
        catch (final NoSuchAlgorithmException e)
        {
            status = Status.FAILED_UNKNOWN_ALGORITHM;
            throw new CryptoProcessException(Status.FAILED_UNKNOWN_ALGORITHM, e);
        }
        catch (final InvalidKeyException e)
        {
            status = Status.FAILED_OTHER;
            throw new CryptoProcessException(Status.FAILED_OTHER, e);
        }
        catch (final XZFormatException e)
        {
            status = Status.FAILED_COMPRESSION_ERROR;
            throw new CryptoProcessException(Status.FAILED_IO, e);
        }
        catch (final IOException e)
        {
            status = Status.FAILED_IO;
            throw new CryptoProcessException(Status.FAILED_IO, e);
        }
        finally
        {
            closeIgnoreException(source);
            closeIgnoreException(output);
        }
    }

    private void writeHeader() throws IOException
    {
        output.write(Convert.toBytes(HEADER[0]));
        output.write(Convert.toBytes(HEADER[1]));
        output.write(Convert.toBytes(HEADER[2]));
        String algorithms = cipher + "/" + hash;
        if (version.compareTo(Version._201406) >= 0)
            algorithms = algorithms.concat("/" + mode);
        output.write((byte)algorithms.length());
        output.write(algorithms.getBytes());
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

        if (!directory && name != null && version.compareTo(Version._201501) >= 0)
        {
            output.write(Convert.toBytes((byte)Tag.FILENAME.value));
            output.write(Convert.toBytes((short)name.length()));
            output.write(name.getBytes());
        }
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
    }

    private int countEntries(final String dir) throws IOException
    {
        int c = 0;
        File[] files =  new File(dir).listFiles();
        if (files == null)
            return c;
        for (final File file : files)
            if (file.isDirectory())
                c += countEntries(dir + File.separator + file.getName());
            else if (file.isFile())
                c++;
        /*
         *  If, and when, Android supports Java7 NIO:
        final LinkOption linkOptions = follow ? null : LinkOption.NOFOLLOW_LINKS;
        for (final File file : new File(dir).listFiles())
        {
            final Path p = FileSystems.getDefault().getPath(file.getPath());
            if (Files.isDirectory(p, linkOptions))
                c += countEntries(dir + File.separator + file.getName());
            else if (Files.isRegularFile(p, linkOptions))
                c++;
            else if (Files.isSymbolicLink(p))
                c++;
        }
         */
        return c;
    }

    private void encryptDirectory(final String dir) throws IOException
    {
        /*
         *  If, and when, Android supports Java7 NIO:
        final LinkOption linkOptions = follow ? null : LinkOption.NOFOLLOW_LINKS;
         */
        File[] files =  new File(dir).listFiles();
        if (files == null)
            return;
        for (final File file : files)
        {
            if (status != Status.RUNNING)
                break;

            final FileType ft;
            if (file.isDirectory())
                ft = FileType.DIRECTORY;
            else if (file.isFile())
                ft = FileType.REGULAR;
            /*
             *  If, and when, Android supports Java7 NIO:
            final Path p = FileSystems.getDefault().getPath(file.getPath());
            Path ln = null;
            if (Files.isDirectory(p, linkOptions))
                ft = FileType.DIRECTORY;
            else if (Files.isRegularFile(p, linkOptions))
            {
                //Files.isSameFile(path, path2);
                if (inodes.containsKey(0L))
                {
                    ft = FileType.LINK;
                    ln = inodes.get(0L);
                }
                else
                {
                    ft = FileType.REGULAR;
                    inodes.put(0L, p);
                }
            }
            else if (Files.isSymbolicLink(p))
            {
                ft = FileType.SYMLINK;
                ln = Files.readSymbolicLink(p);
            }
             */
            else
                continue;

            hashAndWrite(Convert.toBytes((byte)ft.value));
            final String name = dir + File.separator + file.getName();
            final String nm = name.substring(root.length() + 1);
            hashAndWrite(Convert.toBytes((long)nm.length()));
            hashAndWrite(nm.getBytes());

            switch (ft)
            {
                case DIRECTORY:
                    encryptDirectory(name);
                    break;
                case SYMLINK:
                case LINK:
                case REGULAR:
                    source = new FileInputStream(file);
                    current.offset = 0;
                    current.size = file.length();
                    hashAndWrite(Convert.toBytes(current.size));
                    encryptFile();
                    current.offset = current.size;
                    source.close();
                    source = null;
                    break;
            }
            total.offset++;
        }
    }

    private void encryptFile() throws IOException
    {
        final byte[] buffer = new byte[BLOCK_SIZE];
        for (current.offset = 0; current.offset < current.size && status == Status.RUNNING; current.offset += BLOCK_SIZE)
        {
            final int r = source.read(buffer, 0, BLOCK_SIZE);
            hashAndWrite(buffer, r);
        }
    }

    private void hashAndWrite(final byte[] b) throws IOException
    {
        hashAndWrite(b, b.length);
    }

    private void hashAndWrite(final byte[] b, final int l) throws IOException
    {
        output.write(b, 0, l);
        checksum.update(b, 0, l);
    }
}
