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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.albinoloverats.android.encrypt.io.EncryptedFileInputStream;
import net.albinoloverats.android.encrypt.misc.Convert;

import org.tukaani.xz.XZFormatException;
import org.tukaani.xz.XZInputStream;

public class Decrypt extends Crypto
{
	@Override
	public int onStartCommand(final Intent intent, final int flags, final int startId)
	{
		final String source = intent.getStringExtra("source");
		final String output = intent.getStringExtra("output");
		key = intent.getByteArrayExtra("key");
		raw  = intent.getBooleanExtra("raw", raw);

		try
		{
			final File in = new File(source);
			this.source = new EncryptedFileInputStream(in);
			name = in.getName();
			final File out = new File(output);
			if (out.exists() && !out.isDirectory())
				this.output = new FileOutputStream(output);
			path = output;
		}
		catch (final FileNotFoundException e)
		{
			status = Status.FAILED_IO;
		}
		if (raw)
		{
			cipher = intent.getStringExtra("cipher");
			hash   = intent.getStringExtra("hash");
			mode   = intent.getStringExtra("mode");
		}

		intent.putExtra("encrypting", false);
		return super.onStartCommand(intent, flags, startId);
	}

	@Override
	protected void process() throws CryptoProcessException
	{
		try
		{
			status = Status.RUNNING;

			if (raw)
				version = Version.CURRENT;
			else
				readVersion();

			boolean extraRandom = true;
			XIV ivType = XIV.RANDOM;
			switch (version)
			{
				case _201108:
				case _201110:
					ivType = XIV.BROKEN;
				case _201211:
					extraRandom = false;
					break;
				case _201302:
				case _201311:
				case _201406:
					ivType = XIV.SIMPLE;
					break;
				case _201501:
				case CURRENT:
				default:
			}

			checksum = ((EncryptedFileInputStream) source).encryptionInit(cipher, hash, mode, key, ivType);

			if (!raw)
			{
				if (extraRandom)
					skipRandomData();
				readVerificationSum();
				skipRandomData();
			}
			readMetadata();
			if (extraRandom && !raw)
				skipRandomData();

			source = compressed ? new XZInputStream(source) : source;

			checksum.reset();

			if (directory)
				decryptDirectory(path);
			else
			{
				current.size = total.size;
				total.size = 1;
				if (blockSize > 0)
					decryptStream();
				else
					decryptFile();
			}

			if (version != Version._201108 && !raw)
			{
				final byte[] check = new byte[checksum.hashSize()];
				int err = source.read(check);
				final byte[] digest = checksum.digest();
				if (err < 0 || !Arrays.equals(check, digest))
					status = Status.WARNING_CHECKSUM;
			}

			if (status == Status.RUNNING)
				status = Status.SUCCESS;
		}
		catch (final CryptoProcessException e)
		{
			status = e.code;
			throw e;
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
			throw new CryptoProcessException(Status.FAILED_COMPRESSION_ERROR, e);
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

	private void readVersion() throws CryptoProcessException, IOException
	{
		final byte[] header = new byte[Long.SIZE / Byte.SIZE];
		for (int i = 0; i < HEADER.length; i++)
			source.read(header, 0, header.length);

		final byte[] b = new byte[source.read()];
		source.read(b);

		final String a = new String(b);
		cipher = a.substring(0, a.indexOf('/'));
		hash = a.substring(a.indexOf('/') + 1);
		if (hash.contains("/"))
		{
			hash = a.substring(a.indexOf('/') + 1, a.lastIndexOf('/'));
			mode = a.substring(a.lastIndexOf('/') + 1);
		}
		else
			mode = ModeFactory.CBC_MODE;

		if ((version = Version.parseMagicNumber(Convert.longFromBytes(header), null)) == null)
			throw new CryptoProcessException(Status.FAILED_UNKNOWN_VERSION);
	}

	private void readVerificationSum() throws CryptoProcessException, IOException
	{
		final byte buffer[] = new byte[Long.SIZE / Byte.SIZE];
		source.read(buffer);
		final long x = Convert.longFromBytes(buffer);
		source.read(buffer);
		final long y = Convert.longFromBytes(buffer);
		source.read(buffer);
		final long z = Convert.longFromBytes(buffer);
		if ((x ^ y) != z)
			throw new CryptoProcessException(Status.FAILED_DECRYPTION);
	}

	private void readMetadata() throws CryptoProcessException, IOException
	{
		final File f = new File(path);
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
					blockSize = (int)Convert.longFromBytes(v);
					break;
				case COMPRESSED:
					compressed = Convert.booleanFromBytes(v);
					break;
				case DIRECTORY:
					directory = Convert.booleanFromBytes(v);
					break;
				case FILENAME:
					name = new String(v);
					break;
			}
		}
		if (directory)
		{
			if (!f.exists())
				f.mkdirs();
			else if (!f.isDirectory())
				throw new CryptoProcessException(Status.FAILED_OUTPUT_MISMATCH);
		}
		else
		{
			if (!f.exists() || f.isFile())
				output = new FileOutputStream(f);
			else if (f.isDirectory())
				output = new FileOutputStream(f.getAbsolutePath() + File.separatorChar + (name != null ? name : "decrypted"));
			else
				throw new CryptoProcessException(Status.FAILED_OUTPUT_MISMATCH);
		}
		if (output == null && !directory)
		{
			if (!f.exists())
				output = new FileOutputStream(f);
			else if (!f.isFile())
				throw new CryptoProcessException(Status.FAILED_OUTPUT_MISMATCH);
		}
	}

	private void skipRandomData() throws IOException
	{
		final byte[] b = new byte[source.read()];
		source.read(b);
	}

	private void decryptDirectory(final String dir) throws CryptoProcessException, IOException
	{
		boolean linkError = false;
		for (total.offset = 0; total.offset < total.size && status == Status.RUNNING; total.offset++)
		{
			byte[] b = new byte[Byte.SIZE / Byte.SIZE];
			readAndHash(b);
			final FileType t = FileType.fromID((int)b[0]);
			b = new byte[Long.SIZE / Byte.SIZE];
			readAndHash(b);
			long l = Convert.longFromBytes(b);
			b = new byte[(int)l];
			readAndHash(b);
			final String nm = dir + File.separator + new String(b);
			switch (t)
			{
				case DIRECTORY:
					new File(nm).mkdirs();
					break;
				case REGULAR:
					current.offset = 0;
					b = new byte[Long.SIZE / Byte.SIZE];
					readAndHash(b);
					current.size = Convert.longFromBytes(b);
					output = new FileOutputStream(nm);
					decryptFile();
					current.offset = current.size;
					output.close();
					output = null;
					break;
				case LINK:
				case SYMLINK:
					/*
					 * When, or rather if, Android supports more
					 * of Java NIO: we will handle links
					 */
					b = new byte[Long.SIZE / Byte.SIZE];
					readAndHash(b);
					l = Convert.longFromBytes(b);
					b = new byte[(int)l];
					readAndHash(b);
					final String ln = dir + File.separator + new String(b);
					if (t == FileType.LINK)
					{
						/* As with Windows, just copy the file */
						FileChannel sfc = null;
						FileChannel dfc = null;
						try
						{
							sfc = new FileInputStream(new File(ln)).getChannel();
							dfc = new FileOutputStream(new File(nm)).getChannel();
							dfc.transferFrom(sfc, 0, sfc.size());
						}
						finally
						{
							if (sfc != null)
								sfc.close();
							if (dfc != null)
								dfc.close();
						}
					}
					else
						linkError = true;
					break;
			}
		}
		if (linkError)
			status = Status.WARNING_LINK;
	}

	private void decryptStream() throws IOException
	{
		boolean b = true;
		byte[] buffer = new byte[blockSize];
		while (b && status == Status.RUNNING)
		{
			b = source.read() == 1;
			source.read(buffer);
			int r = blockSize;
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
	}

	private void decryptFile() throws IOException
	{
		final byte[] buffer = new byte[BLOCK_SIZE];
		for (current.offset = 0; current.offset < current.size && status == Status.RUNNING; current.offset += BLOCK_SIZE)
		{
			int j = BLOCK_SIZE;
			if (current.offset + BLOCK_SIZE > current.size)
				j = (int)(BLOCK_SIZE - (current.offset + BLOCK_SIZE - current.size));
			final int r = readAndHash(buffer, j);
			output.write(buffer, 0, r);
		}
	}

	private int readAndHash(final byte[] b) throws IOException
	{
		return readAndHash(b, b.length);
	}

	private int readAndHash(final byte[] b, final int l) throws IOException
	{
		final int r = source.read(b, 0, l);
		checksum.update(b, 0, l);
		return r;
	}
}
