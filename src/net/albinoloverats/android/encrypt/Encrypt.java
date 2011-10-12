/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.util.PRNG;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Encrypt extends Thread implements Runnable
{
    public enum Status
    {
        NOT_STARTED,
        RUNNING,
        SUCCEEDED,
        CANCELLED,
        FAILED_UNKNOWN,
        FAILED_ALGORITHM,
        FAILED_KEY,
        FAILED_IO,
        FAILED_DECRYPTION,
        FAILED_UNKNOWN_TAG,
        FAILED_CHECKSUM;

        private String additional;

        public void setAdditional(final String additional)
        {
            this.additional = additional;
        }

        public String getAdditional()
        {
            return additional;
        }
    }

    private enum MetaData
    {
        SIZE((byte)0),
        BLOCKED((byte)1);

        private final byte tag;

        private MetaData(final byte tag)
        {
            this.tag = tag;
        }

        public byte getTagValue()
        {
            return tag;
        }

        public static MetaData getFromTagValue(final byte tag)
        {
            for (final MetaData m : MetaData.values())
                if (m.getTagValue() == tag)
                    return m;
            return null;
        }
    }

    private static final long HEADER_VERSION_201108 = 0x72761df3e497c983L;
    private static final long HEADER_VERSION_201110 = 0xbb116f7d00201110L;
    private static final long[] HEADER = { 0x3697de5d96fca0faL, 0xc845c2fa95e2f52dL, HEADER_VERSION_201110 };

    private static final int BLOCK_SIZE = 1024;

    private File sourceFile;
    private File outputFile;
    private byte[] keyData;
    private String hashName;
    private String cipherName;

    private boolean encrypting = true;

    private long decryptedSize = 0;
    private long bytesProcessed = 0;

    private Status status = Status.NOT_STARTED;

    public Encrypt(final File sourceFile, final File outputFile, final byte[] keyData, final String hashName, final String cipherName)
    {
        this.sourceFile = sourceFile;
        this.outputFile = outputFile;
        this.keyData = keyData;
        this.hashName = hashName;
        this.cipherName = cipherName;
        encrypting = true;
    }

    public Encrypt(final File sourceFile, final File outputFile, final byte[] keyData)
    {
        this.sourceFile = sourceFile;
        this.outputFile = outputFile;
        this.keyData = keyData;
        encrypting = false;
    }

    @Override
    public void run()
    {
        this.stream = null;
        this.block = 0;
        this.offset = new int[3];

        status = Status.RUNNING;
        try
        {
            if (encrypting)
                encrypt();
            else
                decrypt();
            status = Status.SUCCEEDED;
        }
        catch (final InterruptedException e)
        {
            status = Status.CANCELLED;
        }
        catch (final NoSuchAlgorithmException e)
        {
            status = Status.FAILED_ALGORITHM;
            status.setAdditional(e.getMessage());
        }
        catch (final InvalidKeyException e)
        {
            status = Status.FAILED_KEY;
        }
        catch (final InvalidParameterException e)
        {
            status = Status.FAILED_DECRYPTION;
        }
        catch (final UnsupportedEncodingException e)
        {
            status = Status.FAILED_UNKNOWN_TAG;
        }
        catch (final SignatureException e)
        {
            status = Status.FAILED_CHECKSUM;
        }
        catch (final IOException e)
        {
            status = Status.FAILED_IO;
        }
        catch (final Exception e)
        {
            status = Status.FAILED_UNKNOWN;
        }
    }

    public long getDecryptedSize()
    {
        return decryptedSize;
    }

    public long getBytesProcessed()
    {
        return bytesProcessed;
    }

    public Status getStatus()
    {
        return status;
    }

    public static boolean fileEncrypted(final File f)
    {
        FileInputStream in = null;
        try
        {
            in = new FileInputStream(f);
            byte[] header = new byte[Long.SIZE / Byte.SIZE];
            for (int i = 0; i < 2; i++)
            {
                in.read(header, 0, header.length);
                if (Convert.longFromBytes(header) != HEADER[i])
                    return false;
            }
            in.read(header, 0, header.length);
            final long encryptedVersion = Convert.longFromBytes(header);
            if (encryptedVersion == HEADER_VERSION_201108)
                return true;
            else if (encryptedVersion == HEADER_VERSION_201110)
                return true;
            return false;
        }
        catch (final IOException e)
        {
            return false;
        }
        finally
        {
            try
            {
                if (in != null)
                    in.close();
            }
            catch (final Exception e)
            {
                ;
            }
        }        
    }

    private void encrypt() throws InterruptedException, IOException, NoSuchAlgorithmException, InvalidKeyException
    {
        final IMessageDigest hash = AlgorithmNames.getHashAlgorithm(hashName);
        final IBlockCipher cipher = AlgorithmNames.getCipherAlgorithm(cipherName);
        final int blockLength = cipher.defaultBlockSize();
        final IMode crypt = ModeFactory.getInstance("CBC", cipher, blockLength);

        FileOutputStream out = null;
        FileInputStream in = null;
        try
        {
            out = new FileOutputStream(outputFile);
            /*
             * write the default header
             */
            out.write(Convert.toBytes(HEADER[0]));
            out.write(Convert.toBytes(HEADER[1]));
            out.write(Convert.toBytes(HEADER[2]));
            final String algos = cipherName + "/" + hashName;
            out.write((byte)algos.length());
            out.write(algos.getBytes());
            /*
             * setup crypto algorithms
             */
            hash.update(keyData, 0, keyData.length);
            final byte[] key = hash.digest();
            final Map<String, Object> attributes = new HashMap<String, Object>();
            final int keyLength = AlgorithmNames.getCipherAlgorithmKeySize(cipherName) / Byte.SIZE;
            final byte[] correctedKey = new byte[keyLength];
            System.arraycopy(key, 0, correctedKey, 0, keyLength < key.length ? keyLength : key.length);
            attributes.put(IMode.KEY_MATERIAL, correctedKey);
            attributes.put(IMode.CIPHER_BLOCK_SIZE, Integer.valueOf(blockLength));
            attributes.put(IMode.STATE, Integer.valueOf(IMode.ENCRYPTION));
            hash.reset();
            hash.update(key, 0, key.length);
            final byte[] iv = hash.digest();
            final byte[] correctedIV = new byte[keyLength];
            System.arraycopy(iv, 0, correctedIV, 0, keyLength < key.length ? keyLength : key.length);
            attributes.put(IMode.IV, correctedIV);
            crypt.init(attributes);
            /*
             * write simple addition (x ^ y = z) where x, y and random
             * 64bit signed integers
             */
            byte buffer[] = new byte[Long.SIZE / Byte.SIZE];
            PRNG.nextBytes(buffer);
            final long x = Convert.longFromBytes(buffer);
            PRNG.nextBytes(buffer);
            final long y = Convert.longFromBytes(buffer);
            encryptedWrite(out, Convert.toBytes(x), crypt);
            encryptedWrite(out, Convert.toBytes(y), crypt);
            encryptedWrite(out, Convert.toBytes(x ^ y), crypt);
            /*
             * write a random length of random bytes
             */
            buffer = new byte[Short.SIZE / Byte.SIZE];
            PRNG.nextBytes(buffer);
            short sr = (short)(Convert.shortFromBytes(buffer) & 0x00FF);
            buffer = new byte[sr];
            PRNG.nextBytes(buffer);
            encryptedWrite(out, Convert.toBytes((byte)sr), crypt);
            encryptedWrite(out, buffer, crypt);
            /*
             * write file metadata
             */
            encryptedWrite(out, Convert.toBytes((byte)2), crypt);

            encryptedWrite(out, Convert.toBytes(MetaData.SIZE.getTagValue()), crypt);
            encryptedWrite(out, Convert.toBytes((short)(Long.SIZE / Byte.SIZE)), crypt);
            decryptedSize = sourceFile.length();
            encryptedWrite(out, Convert.toBytes(decryptedSize), crypt);

            encryptedWrite(out, Convert.toBytes(MetaData.BLOCKED.getTagValue()), crypt);
            encryptedWrite(out, Convert.toBytes((short)(Long.SIZE / Byte.SIZE)), crypt);
            encryptedWrite(out, Convert.toBytes((long)BLOCK_SIZE), crypt);

            /*
             * main encryption loop
             */
            in = new FileInputStream(sourceFile);
            buffer = new byte[BLOCK_SIZE];
            hash.reset();
            boolean b1 = true;
            while (b1)
            {
                if (interrupted())
                    throw new InterruptedException();
                PRNG.nextBytes(buffer);
                final int r = in.read(buffer, 0, BLOCK_SIZE);
                if (r < BLOCK_SIZE)
                    b1 = false;
                encryptedWrite(out, Convert.toBytes(b1), crypt);
                encryptedWrite(out, buffer, crypt);
                hash.update(buffer, 0, r);
                if (!b1)
                    encryptedWrite(out, Convert.toBytes((long)r), crypt);
                bytesProcessed += r;
            }
            /*
             * write check sum of data
             */
            final byte[] digest = hash.digest();
            encryptedWrite(out, digest, crypt);
            /*
             * add some random data at the end
             */
            buffer = new byte[Short.SIZE / Byte.SIZE];
            PRNG.nextBytes(buffer);
            sr = Convert.shortFromBytes(buffer);
            buffer = new byte[sr];
            PRNG.nextBytes(buffer);
            encryptedWrite(out, buffer, crypt);
            encryptedWrite(out, null, crypt);
        }
        finally
        {
            try
            {
                if (out != null)
                    out.close();
                if (in != null)
                    in.close();
            }
            catch (final Exception e)
            {
                ;
            }
        }
    }

    private void decrypt() throws InterruptedException,  IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterException, UnsupportedEncodingException, SignatureException
    {
        FileInputStream in = null;
        FileOutputStream out = null;
        try
        {
            /*
             * read the default header
             */
            in = new FileInputStream(sourceFile);
            for (int i = 0; i < 3; i++)
            {
                byte[] header = new byte[Long.SIZE / Byte.SIZE];
                in.read(header, 0, header.length);
            }
            /*
             * initialise algorithms
             */
            int length = in.read();
            byte[] buffer = new byte[length];
            in.read(buffer, 0, buffer.length);
            final String algos = new String(buffer);
            final String cipherName = algos.substring(0, algos.indexOf('/'));
            final String hashName = algos.substring(algos.indexOf('/') + 1);
            final IMessageDigest hash = AlgorithmNames.getHashAlgorithm(hashName);
            final IBlockCipher cipher = AlgorithmNames.getCipherAlgorithm(cipherName);
            final int blockLength = cipher.defaultBlockSize();
            final IMode crypt = ModeFactory.getInstance("CBC", cipher, blockLength);
            /*
             * validate key hash
             */
            hash.update(keyData, 0, keyData.length);
            final byte[] key = hash.digest();
            final Map<String, Object> attributes = new HashMap<String, Object>();
            final int keyLength = AlgorithmNames.getCipherAlgorithmKeySize(cipherName) / Byte.SIZE;
            final byte[] correctedKey = new byte[keyLength];
            System.arraycopy(key, 0, correctedKey, 0, keyLength < key.length ? keyLength : key.length);
            attributes.put(IMode.KEY_MATERIAL, correctedKey);
            attributes.put(IMode.CIPHER_BLOCK_SIZE, Integer.valueOf(blockLength));
            attributes.put(IMode.STATE, Integer.valueOf(IMode.DECRYPTION));
            hash.reset();
            hash.update(key, 0, key.length);
            final byte[] iv = hash.digest();
            final byte[] correctedIV = new byte[keyLength];
            System.arraycopy(iv, 0, correctedIV, 0, keyLength < key.length ? keyLength : key.length);
            attributes.put(IMode.IV, correctedIV);
            crypt.init(attributes);
            /*
             * read three 64bit signed integers and assert that x ^ y = z
             */
            buffer = new byte[Long.SIZE / Byte.SIZE];
            encryptedRead(in, buffer, crypt);
            final long x = Convert.longFromBytes(buffer);
            encryptedRead(in, buffer, crypt);
            final long y = Convert.longFromBytes(buffer);
            encryptedRead(in, buffer, crypt);
            final long z = Convert.longFromBytes(buffer);
            if ((x ^ y) != z)
                throw new InvalidParameterException();
            /*
             * skip random data
             */
            byte[] singleByte = new byte[Byte.SIZE / Byte.SIZE];
            encryptedRead(in, singleByte, crypt);
            buffer = new byte[((short)Convert.byteFromBytes(singleByte) & 0x00FF)];
            encryptedRead(in, buffer, crypt);
            /*
             * read original file metadata
             */
            encryptedRead(in, singleByte, crypt);
            final byte tags = Convert.byteFromBytes(singleByte);
            byte[] doubleByte = new byte[Short.SIZE / Byte.SIZE];
            int blockSize = 0;
            for (int i = 0; i < tags; i++)
            {
                encryptedRead(in, singleByte, crypt);
                encryptedRead(in, doubleByte, crypt);
                final MetaData t = MetaData.getFromTagValue(Convert.byteFromBytes(singleByte));
                final short l = Convert.shortFromBytes(doubleByte);
                buffer = new byte[l];
                encryptedRead(in, buffer, crypt);
                switch (t)
                {
                    case SIZE:
                        decryptedSize = Convert.longFromBytes(buffer); 
                        break;
                    case BLOCKED:
                        blockSize = (int)Convert.longFromBytes(buffer);
                        break;
                    default:
                        throw new UnsupportedEncodingException();
                }
            }

            out = new FileOutputStream(outputFile);
            /*
             * main decryption loop
             */
            hash.reset();
            if (blockSize > 0)
            {
                final byte[] booleanBytes = new byte[1];
                final byte[] longBytes = new byte[Long.SIZE / Byte.SIZE];
                boolean booleanByte = true;
                buffer = new byte[BLOCK_SIZE];
                while (booleanByte)
                {
                    if (interrupted())
                        throw new InterruptedException();
                    encryptedRead(in, booleanBytes, crypt);
                    booleanByte = Convert.booleanFromBytes(booleanBytes);
                    int r = BLOCK_SIZE;
                    encryptedRead(in, buffer, crypt);
                    if (!booleanByte)
                    {
                        encryptedRead(in, longBytes, crypt);
                        r = (int)Convert.longFromBytes(longBytes);
                        byte[] tmp = new byte[r];
                        System.arraycopy(buffer, 0, tmp, 0, r);
                        buffer = new byte[r];
                        System.arraycopy(tmp, 0, buffer, 0, r);
                    }
                    hash.update(buffer, 0, r);
                    out.write(buffer);
                    bytesProcessed += r;
                }
            }
            else
                for (bytesProcessed = 0; bytesProcessed < decryptedSize; bytesProcessed += blockLength)
                {
                    if (interrupted())
                        throw new InterruptedException();
                    int j = blockLength;
                    if (bytesProcessed + blockLength > decryptedSize)
                        j = (int)(blockLength - (bytesProcessed + blockLength - decryptedSize));
                    buffer = new byte[j];
                    encryptedRead(in, buffer, crypt);
                    hash.update(buffer, 0, j);
                    out.write(buffer);
                }
            /*
             * compare checksums of plain data
             */
            buffer = new byte[hash.hashSize()];
            encryptedRead(in, buffer, crypt);
            final byte[] digest = hash.digest();
            if (!Arrays.equals(buffer, digest))
                throw new SignatureException();
        }
        finally
        {
            try
            {
                if (out != null)
                    out.close();
                if (in != null)
                    in.close();
            }
            catch (final Exception e)
            {
                ;
            }
        }
    }

    private byte[] stream = null;
    private int block = 0;
    private int[] offset = { 0, 0, 0 };
    
    private void encryptedWrite(final FileOutputStream out, final byte[] bytes, final IMode cipher) throws IOException
    {
        if (block == 0)
            block = cipher.defaultBlockSize();
        if (stream == null)
            stream = new byte[block];
        int[] remainder = { bytes.length, block - offset[0] };
        if (bytes == null)
        {
            final byte[] x = new byte[remainder[1]];
            PRNG.nextBytes(x);
            System.arraycopy(x, 0, stream, offset[0], remainder[1]);
            final byte[]eBytes = new byte[block];
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
            final byte[]eBytes = new byte[block];
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

    private void encryptedRead(final FileInputStream in, byte[] bytes, final IMode cipher) throws IOException
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
