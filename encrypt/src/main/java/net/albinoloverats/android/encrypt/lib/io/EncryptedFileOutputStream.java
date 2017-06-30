/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2017, albinoloverats ~ Software Development
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
import gnu.crypto.util.PRNG;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.albinoloverats.android.encrypt.lib.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.lib.crypt.XIV;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

public class EncryptedFileOutputStream extends FileOutputStream
{
	private static final int PBKDF2_ITERATIONS = 1024;

	private final ECCFileOutputStream eccFileOutputStream;

	private IMode cipher;

	private byte[] buffer = null;
	private int blockSize = 0;
	private int[] offset = { 0, 0 };

	private boolean open = true;

	public EncryptedFileOutputStream(final File file) throws FileNotFoundException
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
		eccFileOutputStream = new ECCFileOutputStream(file);
	}

	public HashMAC initialiseEncryption(final String c, final String h, final String m, String a, final byte[] k, final XIV ivType, final boolean useKDF) throws NoSuchAlgorithmException, InvalidKeyException, LimitReachedException, IOException
	{
		final IMessageDigest hash = CryptoUtils.getHashAlgorithm(h);
		final IBlockCipher cipher = CryptoUtils.getCipherAlgorithm(c);
		final HMac mac = CryptoUtils.getMacAlgorithm(a);

		blockSize = cipher.defaultBlockSize();
		this.cipher = ModeFactory.getInstance(m, cipher, blockSize);
		hash.update(k, 0, k.length);
		final byte[] keySource = hash.digest();
		Map<String, Object> attributes;
		int keyLength = CryptoUtils.getCipherAlgorithmKeySize(c) / Byte.SIZE;
		byte[] key = new byte[keyLength];

		final int saltLength = keyLength;
		final byte[] salt = new byte[saltLength];

		final IMac keyMac = CryptoUtils.getMacAlgorithm(CryptoUtils.hmacFromHash(h));

		if (useKDF)
		{
			PRNG.nextBytes(salt);
			eccFileOutputStream.write(salt);

			final PBKDF2 keyGen = new PBKDF2(keyMac);
			attributes = new HashMap<>();
			attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
			attributes.put(IPBE.SALT, salt);
			attributes.put(IPBE.ITERATION_COUNT, PBKDF2_ITERATIONS);
			keyGen.init(attributes);
			keyGen.nextBytes(key);
		}
		else
			System.arraycopy(keySource, 0, key, 0, keyLength < keySource.length ? keyLength : keySource.length);

		attributes = new HashMap<>();
		attributes.put(IBlockCipher.KEY_MATERIAL, key);
		attributes.put(IBlockCipher.CIPHER_BLOCK_SIZE, blockSize);
		attributes.put(IMode.STATE, IMode.ENCRYPTION);
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
				PRNG.nextBytes(iv);
				eccFileOutputStream.write(iv);
				break;
		}
		attributes.put(IMode.IV, iv);
		this.cipher.init(attributes);
		buffer = new byte[blockSize];

		final int macLength = CryptoUtils.getHashAlgorithm(CryptoUtils.hashFromHmac(a)).blockSize();
		key = new byte[macLength];
		final PBKDF2 keyGen = new PBKDF2(keyMac);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
		attributes.put(IPBE.SALT, salt);
		attributes.put(IPBE.ITERATION_COUNT, PBKDF2_ITERATIONS);
		keyGen.init(attributes);
		keyGen.nextBytes(key);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, key);
		mac.init(attributes);

		return new HashMAC(hash, mac);
	}

	public void initaliseECC()
	{
		eccFileOutputStream.initalise();
	}

	@Override
	public void close() throws IOException
	{
		if (!open)
			return;
		if (cipher != null)
		{
			final int[] remainder = { 0, blockSize - offset[0] };
			final byte[] x = new byte[remainder[1]];
			PRNG.nextBytes(x);
			System.arraycopy(x, 0, buffer, offset[0], remainder[1]);
			final byte[] eBytes = new byte[blockSize];
			cipher.update(buffer, 0, eBytes, 0);
			eccFileOutputStream.write(eBytes);
		}
		eccFileOutputStream.close();
		open = false;
	}

	@Override
	public FileChannel getChannel()
	{
		return eccFileOutputStream.getChannel();
	}

	@Override
	public void write(final byte[] bytes) throws IOException
	{
		if (cipher == null)
		{
			eccFileOutputStream.write(bytes);
			return;
		}
		final int[] remainder = { bytes.length, blockSize - offset[0] };
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
			final byte[] eBytes = new byte[blockSize];
			cipher.update(buffer, 0, eBytes, 0);
			eccFileOutputStream.write(eBytes);
			offset[0] = 0;
			buffer = new byte[blockSize];
			offset[1] += remainder[1];
			remainder[0] -= remainder[1];
			remainder[1] = blockSize - offset[0];
		}
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
