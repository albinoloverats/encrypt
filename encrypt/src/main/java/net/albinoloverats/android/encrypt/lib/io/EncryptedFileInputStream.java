/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2021, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.lib.io;

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.HMac;
import gnu.crypto.mac.IMac;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.prng.IPBE;
import gnu.crypto.prng.LimitReachedException;
import gnu.crypto.prng.PBKDF2;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.albinoloverats.android.encrypt.lib.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.lib.crypt.XIV;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

public class EncryptedFileInputStream extends FileInputStream
{
	private final ECCFileInputStream eccFileInputStream;

	private IMode cipher;

	private byte[] buffer = null;
	private int blockSize = 0;
	private final int[] offset = { 0, 0, 0 }; /* bytes available, requested, ready */

	public EncryptedFileInputStream(final File file) throws FileNotFoundException
	{
		super(file);
		try
		{
			super.close();
		}
		catch (final IOException e)
		{
			// ignored
		}
		eccFileInputStream = new ECCFileInputStream(file);
	}

	public HashMAC initialiseDecryption(final String c, final String h, final String m, final String a, final int kdfIterations, final byte[] k, final XIV ivType, final boolean useKDF) throws NoSuchAlgorithmException, InvalidKeyException, LimitReachedException, IOException
	{
		final IMessageDigest hash = CryptoUtils.getHashAlgorithm(h);
		final IBlockCipher blockCipher = CryptoUtils.getCipherAlgorithm(c);

		blockSize = blockCipher.defaultBlockSize();
		cipher = ModeFactory.getInstance(m, blockCipher, blockSize);
		hash.update(k, 0, k.length);
		final byte[] keySource = hash.digest();
		Map<String, Object> attributes;
		final int keyLength = CryptoUtils.getCipherAlgorithmKeySize(c) / Byte.SIZE;
		byte[] key = new byte[keyLength];

		final int saltLength = keyLength;
		final byte[] salt = new byte[saltLength];

		final IMac keyMac = CryptoUtils.getMacAlgorithm(CryptoUtils.hmacFromHash(h));

		if (useKDF)
		{
			eccFileInputStream.read(salt);

			PBKDF2 keyGen = new PBKDF2(keyMac);
			attributes = new HashMap<>();
			attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
			attributes.put(IPBE.SALT, salt);
			attributes.put(IPBE.ITERATION_COUNT, kdfIterations);
			keyGen.init(attributes);
			keyGen.nextBytes(key);
		}
		else
			System.arraycopy(keySource, 0, key, 0, keyLength < keySource.length ? keyLength : keySource.length);

		attributes = new HashMap<>();
		attributes.put(IBlockCipher.KEY_MATERIAL, key);
		attributes.put(IBlockCipher.CIPHER_BLOCK_SIZE, blockSize);
		attributes.put(IMode.STATE, IMode.DECRYPTION);
		hash.reset();
		hash.update(keySource, 0, keySource.length);
		final byte[] iv = new byte[ivType != XIV.BROKEN ? blockSize : keyLength];
		switch (ivType)
		{
			case BROKEN:
			case SIMPLE:
				System.arraycopy(hash.digest(), 0, iv, 0, iv.length);
				break;
			case RANDOM:
				eccFileInputStream.read(iv);
				break;
		}
		attributes.put(IMode.IV, iv);
		cipher.init(attributes);
		buffer = new byte[blockSize];

		final HMac mac = CryptoUtils.getMacAlgorithm(a);
		final int macLength = CryptoUtils.getHashAlgorithm(CryptoUtils.hashFromHmac(a)).blockSize();
		key = new byte[macLength];
		PBKDF2 keyGen = new PBKDF2(keyMac);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
		attributes.put(IPBE.SALT, salt);
		attributes.put(IPBE.ITERATION_COUNT, kdfIterations);
		keyGen.init(attributes);
		keyGen.nextBytes(key);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, key);
		mac.init(attributes);

		return new HashMAC(hash, mac);
	}

	public void initialiseECC()
	{
		eccFileInputStream.initalise();
	}

	@Override
	public int available() throws IOException
	{
		if (cipher == null)
			return eccFileInputStream.available();
		return offset[0];
	}

	@Override
	public void close() throws IOException
	{
		eccFileInputStream.close();
	}

	@Override
	public FileChannel getChannel()
	{
		return eccFileInputStream.getChannel();
	}

	@Override
	public int read() throws IOException
	{
		final byte[] b = new byte[Integer.SIZE / Byte.SIZE];
		int err = read(b, 3, 1);
		return err < 0 ? err : Convert.intFromBytes(b);
	}

	@Override
	public int read(final byte[] bytes) throws IOException
	{
		int err = 0;
		if (cipher == null)
			return eccFileInputStream.read(bytes);
		offset[1] = bytes.length;
		offset[2] = 0;
		while (true)
		{
			if (offset[0] >= offset[1])
			{
				System.arraycopy(buffer, 0, bytes, offset[2], offset[1]);
				offset[0] -= offset[1];
				final byte[] x = new byte[blockSize];
				System.arraycopy(buffer, offset[1], x, 0, offset[0]);
				buffer = new byte[blockSize];
				System.arraycopy(x, 0, buffer, 0, offset[0]);
				return err < 0 ? err : offset[1] + offset[2];
			}
			System.arraycopy(buffer, 0, bytes, offset[2], offset[0]);
			offset[2] += offset[0];
			offset[1] -= offset[0];
			offset[0] = 0;
			final byte[] eBytes = new byte[blockSize];
			err = eccFileInputStream.read(eBytes);
			cipher.update(eBytes, 0, buffer, 0);
			offset[0] = blockSize;
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
