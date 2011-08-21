package net.albinoloverats.android.encrypt;

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Encrypt extends Thread implements Runnable
{
    public enum Status
    {
        NOT_STARTED,
        RUNNING,
        SUCCEEDED,
        CANCELLED,
        FAILED_ALGORITHM,
        FAILED_KEY,
        FAILED_IO,
        FAILED_DECRYPTION,
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
        SIZE((byte)0);

        private byte tag;

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

    private static final long[] HEADER = { 0x3697de5d96fca0faL, 0xc845c2fa95e2f52dL, 0x72761df3e497c983L };

    private File sourceFile;
    private File outputFile;
    private byte[] keyData;
    private String hashName;
    private String cipherName;

    private byte[] streamBytes = null;
    private int streamLength = 0;

    private boolean encrypting = true;

    private long decryptedSize = 0;
    private long bytesProcessed = 0;

    private Status status = Status.NOT_STARTED;;

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
        catch (final IOException e)
        {
            status = Status.FAILED_IO;
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
        catch (final SignatureException e)
        {
            status = Status.FAILED_CHECKSUM;
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
            for (int i = 0; i < 3; i++)
            {
                byte[] header = new byte[Long.SIZE / Byte.SIZE];
                in.read(header, 0, header.length);
                if (Convert.longFromBytes(header) != HEADER[i])
                    return false;
            }
            return true;
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
        streamBytes = null;
        streamLength = 0;

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
             * write hash of key data
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
            final long x = new Random().nextLong();
            final long y = new Random().nextLong();
            encryptedWrite(out, Convert.toBytes(x), crypt);
            encryptedWrite(out, Convert.toBytes(y), crypt);
            encryptedWrite(out, Convert.toBytes(x ^ y), crypt);
            /*
             * write a random length of random bytes
             */
            short head_r = (short)(new Random().nextInt() & 0x00FF);
            byte buffer[] = new byte[head_r];
            new Random().nextBytes(buffer);
            encryptedWrite(out, Convert.toBytes((byte)(head_r & 0x00FF)), crypt);
            encryptedWrite(out, buffer, crypt);
            /*
             * write file metadata
             */
            encryptedWrite(out, Convert.toBytes((byte)1), crypt);

            encryptedWrite(out, Convert.toBytes(MetaData.SIZE.getTagValue()), crypt);
            encryptedWrite(out, Convert.toBytes((short)Short.SIZE / Byte.SIZE), crypt);
            decryptedSize = sourceFile.length();
            encryptedWrite(out, Convert.toBytes(decryptedSize), crypt);
            /*
             * main encryption loop
             */
            in = new FileInputStream(sourceFile);
            buffer = new byte[blockLength];
            hash.reset();
            for (bytesProcessed = 0; bytesProcessed < decryptedSize; bytesProcessed += blockLength)
            {
                if (interrupted())
                    throw new InterruptedException();
                int r = blockLength;
                if (bytesProcessed + blockLength > decryptedSize)
                    r = (int)(blockLength - (bytesProcessed + blockLength - decryptedSize));
                buffer = new byte[r];
                in.read(buffer, 0, r);
                hash.update(buffer, 0, r);
                encryptedWrite(out, buffer, crypt);
            }
            /*
             * write check sum of data
             */
            final byte[] digest = hash.digest();
            encryptedWrite(out, digest, crypt);
            /*
             * add some random data at the end
             */
            buffer = new byte[(short)(new Random().nextInt() & 0x00FF)];
            new Random().nextBytes(buffer);
            encryptedWrite(out, buffer, crypt);
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

    private void decrypt() throws InterruptedException,  IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterException, SignatureException
    {
        streamBytes = null;
        streamLength = 0;

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
                    default:
                        break;
                }
            }

            out = new FileOutputStream(outputFile);
            /*
             * main decryption loop
             */
            hash.reset();
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

    private void encryptedWrite(final FileOutputStream out, final byte[] bytes, final IMode cipher) throws IOException
    {
        final int block = cipher.defaultBlockSize();
        if (streamBytes == null)
            streamBytes = new byte[block];
        int bytesWritten = 0, bytesRemaining = bytes.length;
        while ((bytesRemaining + streamLength) >= block)
        {
            System.arraycopy(bytes, bytesWritten, streamBytes, streamLength, block - streamLength);
            final byte[] encryptedBytes = new byte[block];
            cipher.update(streamBytes, 0, encryptedBytes, 0);
            //System.arraycopy(streamBytes, 0, encryptedBytes, 0, block);
            out.write(encryptedBytes);
            bytesWritten += (block - streamLength);
            bytesRemaining -= (block - streamLength);
            streamBytes = new byte[block];
            streamLength = 0;
        }
        System.arraycopy(bytes, bytesWritten, streamBytes, streamLength, bytesRemaining);
        streamLength += bytesRemaining;
        return;
    }

    private void encryptedRead(final FileInputStream in, byte[] bytes, final IMode cipher) throws IOException
    {
        final int block = cipher.defaultBlockSize();
        if (streamBytes == null)
            streamBytes = new byte[2 * block];
        if (streamLength == bytes.length)
        {
            System.arraycopy(streamBytes, 0, bytes, 0, bytes.length);
            streamLength = 0;
            return;
        }
        if (streamLength > bytes.length)
        {
            System.arraycopy(streamBytes, 0, bytes, 0, bytes.length);
            streamLength -= bytes.length;
            System.arraycopy(streamBytes, bytes.length, streamBytes, 0, streamLength);
            return;
        }
        System.arraycopy(streamBytes, 0, bytes, 0, streamLength);
        int i = streamLength;
        streamLength = 0;
        while (i < bytes.length)
        {
            final byte[] encryptedBytes = new byte[block];
            in.read(encryptedBytes, 0, block);
            cipher.update(encryptedBytes, 0, streamBytes, 0);
            //System.arraycopy(encryptedBytes, 0, streamBytes, 0, block);
            int j = block;
            if (i + block > bytes.length)
                j = block - (i + block - bytes.length);
            System.arraycopy(streamBytes, 0, bytes, i, j);
            i += j;
            streamLength = block - j;
        }
        System.arraycopy(streamBytes, block - streamLength, streamBytes, 0, streamLength);
        return;
    }
}
