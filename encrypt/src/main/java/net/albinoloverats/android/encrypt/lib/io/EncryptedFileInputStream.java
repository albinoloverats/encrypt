/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2025, albinoloverats ~ Software Development
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
import gnu.crypto.mac.IMac;
import gnu.crypto.mode.IMode;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.prng.IPBE;
import gnu.crypto.prng.LimitReachedException;
import gnu.crypto.prng.PBKDF2;
import lombok.val;
import net.albinoloverats.android.encrypt.lib.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.lib.crypt.XIV;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class EncryptedFileInputStream extends InputStream
{
	private final ECCFileInputStream eccFileInputStream;

	private IMode cipher;

	private byte[] buffer = null;
	private int blockSize = 0;
	private final int[] offset = { 0, 0, 0 }; /* bytes available, requested, ready */

	public EncryptedFileInputStream(final InputStream stream)
	{
		try
		{
			super.close();
		}
		catch (final IOException e)
		{
			// ignored
		}
		eccFileInputStream = new ECCFileInputStream(stream);
	}

	public HashMAC initialiseDecryption(final String c, final String h, final String m, final String a, final int kdfIterations, final byte[] k, final XIV ivType, final boolean useKDF) throws NoSuchAlgorithmException, InvalidKeyException, LimitReachedException, IOException
	{
		val hash = CryptoUtils.getHashAlgorithm(h);
		val blockCipher = CryptoUtils.getCipherAlgorithm(c);

		blockSize = blockCipher.defaultBlockSize();
		buffer = new byte[blockSize];
		if ((cipher = ModeFactory.getInstance(m, blockCipher, blockSize)) == null)
			throw new NoSuchAlgorithmException(m);

		hash.update(k, 0, k.length);
		val keySource = hash.digest();
		Map<String, Object> attributes;
		val keyLength = CryptoUtils.getCipherAlgorithmKeySize(c) / Byte.SIZE;
		var key = new byte[keyLength];

		val salt = new byte[keyLength];

		val keyMac = CryptoUtils.getMacAlgorithm(CryptoUtils.hmacFromHash(h));

		if (useKDF)
		{
			eccFileInputStream.read(salt);

			val keyGen = new PBKDF2(keyMac);
			attributes = new HashMap<>();
			attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
			attributes.put(IPBE.SALT, salt);
			attributes.put(IPBE.ITERATION_COUNT, kdfIterations);
			keyGen.init(attributes);
			keyGen.nextBytes(key, 0, key.length);
		}
		else
			System.arraycopy(keySource, 0, key, 0, Math.min(keyLength, keySource.length));

		attributes = new HashMap<>();
		attributes.put(IBlockCipher.KEY_MATERIAL, key);
		attributes.put(IBlockCipher.CIPHER_BLOCK_SIZE, blockSize);
		attributes.put(IMode.STATE, IMode.DECRYPTION);
		hash.reset();
		hash.update(keySource, 0, keySource.length);
		val iv = new byte[ivType != XIV.BROKEN ? blockSize : keyLength];
		switch (ivType)
		{
			case BROKEN, SIMPLE:
				System.arraycopy(hash.digest(), 0, iv, 0, iv.length);
				break;
			case RANDOM:
				eccFileInputStream.read(iv);
				break;
		}
		attributes.put(IMode.IV, iv);
		cipher.init(attributes);

		val mac = CryptoUtils.getMacAlgorithm(a);
		val macLength = CryptoUtils.getHashAlgorithm(CryptoUtils.hashFromHmac(a)).blockSize();
		key = new byte[macLength];
		val keyGen = new PBKDF2(keyMac);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, keySource);
		attributes.put(IPBE.SALT, salt);
		attributes.put(IPBE.ITERATION_COUNT, kdfIterations);
		keyGen.init(attributes);
		keyGen.nextBytes(key, 0, key.length);
		attributes = new HashMap<>();
		attributes.put(IMac.MAC_KEY_MATERIAL, key);
		mac.init(attributes);

		return new HashMAC(hash, mac);
	}

	public void initialiseECC()
	{
		eccFileInputStream.initialise();
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
	public int read() throws IOException
	{
		val b = new byte[Integer.SIZE / Byte.SIZE];
		val err = read(b, 3, 1);
		return err < 0 ? err : Convert.intFromBytes(b);
	}

	@Override
	public int read(final byte[] bytes) throws IOException
	{
		if (cipher == null)
			return eccFileInputStream.read(bytes);
		if (bytes.length == 0)
			return 0;

		int copied = 0;
		while (copied < bytes.length)
		{
			if (offset[0] > 0)
			{
				val length = Math.min(offset[0], bytes.length - copied);
				System.arraycopy(buffer, 0, bytes, copied, length);
				offset[0] -= length;
				System.arraycopy(buffer, length, buffer, 0, offset[0]);
				copied += length;
				continue;
			}

			val eBytes = new byte[blockSize];
			val count = eccFileInputStream.read(eBytes);
			if (count < 0)
			{
				if (copied == 0)
					return -1;
				return copied;
			}
			if (count != blockSize)
				throw new EOFException("Truncated encrypted block");
			cipher.update(eBytes, 0, buffer, 0);
			offset[0] = blockSize;
		}
		return copied;
	}

	@Override
	public int read(final byte[] b, final int off, final int len) throws IOException
	{
		if (off < 0 || len < 0 || len > b.length - off)
			throw new IndexOutOfBoundsException();
		if (len == 0)
			return 0;
		val bytes = new byte[len];
		val x = read(bytes);
		if (x > 0)
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
