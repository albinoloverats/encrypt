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

package net.albinoloverats.android.encrypt.io;

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.albinoloverats.android.encrypt.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.misc.Convert;

public class EncryptedFileInputStream extends FileInputStream
{
    private final FileInputStream stream;
    
    private IMode cipher;
    
    private byte[] buffer = null;
    private int blocksize = 0;
    private final int[] offset = { 0, 0, 0 }; /* bytes available, requested, ready */

    public EncryptedFileInputStream(final File file) throws FileNotFoundException
    {
        super(file);
        stream = new FileInputStream(file);
    }
    
    public IMessageDigest encryptionInit(final String cipher, final String hash, final byte[] key, final boolean legacy) throws NoSuchAlgorithmException, InvalidKeyException
    {
        IMessageDigest h = CryptoUtils.getHashAlgorithm(hash);
        final IBlockCipher c = CryptoUtils.getCipherAlgorithm(cipher);
        blocksize = c.defaultBlockSize();
        this.cipher = ModeFactory.getInstance("CBC", c, blocksize);
        h.update(key, 0, key.length);
        final byte[] keySource = h.digest();
        final Map<String, Object> attributes = new HashMap<String, Object>();
        final int keyLength = CryptoUtils.getCipherAlgorithmKeySize(cipher) / Byte.SIZE;
        final byte[] keyOutput = new byte[keyLength];
        System.arraycopy(keySource, 0, keyOutput, 0, keyLength < keySource.length ? keyLength : keySource.length);
        attributes.put(IBlockCipher.KEY_MATERIAL, keyOutput);
        attributes.put(IBlockCipher.CIPHER_BLOCK_SIZE, Integer.valueOf(blocksize));
        attributes.put(IMode.STATE, Integer.valueOf(IMode.DECRYPTION));
        h.reset();
        h.update(keySource, 0, keySource.length);
        final byte[] ivSource = h.digest();
        final byte[] ivOutput = new byte[legacy ? keyLength : blocksize];
        System.arraycopy(ivSource, 0, ivOutput, 0, blocksize < ivSource.length ? blocksize : ivSource.length);
        attributes.put(IMode.IV, ivOutput);
        this.cipher.init(attributes);
        buffer = new byte[blocksize];
        return h;
    }

    @Override
    public int available() throws IOException
    {
        if (cipher == null)
            return super.available();
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
        final byte[] b = new byte[Integer.SIZE / Byte.SIZE];
        read(b, 3, 1);
        return Convert.intFromBytes(b);
    }

    @Override
    public int read(final byte[] bytes) throws IOException
    {
        if (cipher == null)
            return stream.read(bytes);
        offset[1] = bytes.length;
        offset[2] = 0;
        while (true)
        {
            if (offset[0] >= offset[1])
            {
                System.arraycopy(buffer, 0, bytes, offset[2], offset[1]);
                offset[0] -= offset[1];
                final byte[] x = new byte[blocksize];
                System.arraycopy(buffer, offset[1], x, 0, offset[0]);
                buffer = new byte[blocksize];
                System.arraycopy(x, 0, buffer, 0, offset[0]);
                return offset[1] + offset[2];
            }
            System.arraycopy(buffer, 0, bytes, offset[2], offset[0]);
            offset[2] += offset[0];
            offset[1] -= offset[0];
            offset[0] = 0;
            final byte[] eBytes = new byte[blocksize];
            stream.read(eBytes);
            cipher.update(eBytes, 0, buffer, 0);
            offset[0] = blocksize;
        }
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException
    {
        final byte[] bytes = new byte[len];
        final int x = read(bytes);
        System.arraycopy(bytes, 0, b, off, x);
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
