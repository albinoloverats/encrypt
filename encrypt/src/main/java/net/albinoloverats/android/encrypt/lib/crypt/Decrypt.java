/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2024, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.lib.crypt;

import android.app.Service;
import android.content.Intent;
import android.net.Uri;

import net.albinoloverats.android.encrypt.lib.io.EncryptedFileInputStream;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

import org.tukaani.xz.XZFormatException;
import org.tukaani.xz.XZInputStream;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import androidx.documentfile.provider.DocumentFile;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.prng.LimitReachedException;

public class Decrypt extends Crypto
{
	private static final String SELF = ".";

	@Override
	public int onStartCommand(final Intent intent, final int flags, final int startId)
	{
		if (intent == null)
			return Service.START_REDELIVER_INTENT;

		preInit();

		final List<Uri> s = intent.getParcelableArrayListExtra("source");
		final Uri source = s.get(0);
		final Uri output = intent.getParcelableExtra("output");

		try
		{
			contentResolver = getContentResolver();
			this.source = new EncryptedFileInputStream(contentResolver.openInputStream(source));

			final DocumentFile documentFile = DocumentFile.fromSingleUri(this, output);
			name = documentFile.getName();

			if (documentFile.exists() && !documentFile.isDirectory())
				this.output = contentResolver.openOutputStream(output);
			path = documentFile.getUri();
		}
		catch (final FileNotFoundException e)
		{
			status = Status.FAILED_IO;
		}
		if (raw)
		{
			cipher         = intent.getStringExtra("cipher");
			hash           = intent.getStringExtra("hash");
			mode           = intent.getStringExtra("mode");
			mac            = intent.getStringExtra("mac");
			kdfIterations  = intent.getIntExtra("kdf_iterations", KDF_ITERATIONS_DEFAULT);
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

			version = raw ? Version.CURRENT : readVersion();
			if (version == null || status != Status.RUNNING)
				throw new Exception("Could not parse header!");

			boolean extraRandom = true;
			XIV ivType = XIV.RANDOM;
			boolean useMAC = true;
			switch (version)
			{
				case _201108:
				case _201110:
					ivType = XIV.BROKEN;
				case _201211:
					extraRandom = false;
					useMAC = false;
					break;
				case _201302:
				case _201311:
				case _201406:
					ivType = XIV.SIMPLE;
					useMAC = false;
					break;
				case _201501:
				case _201510:
					useMAC = false;
					break;
				case _201709:
					kdfIterations = KDF_ITERATIONS_201709;
					break;
				case _202001:
				case _202201:
				case _202401:
				case CURRENT:
					//kdfIterations = KDF_ITERATIONS_DEFAULT;
					break;
			}

			verification = ((EncryptedFileInputStream)source).initialiseDecryption(cipher, hash, mode, mac, kdfIterations, key, ivType, useMAC);

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

			verification.hash.reset();

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
				final byte[] digest = verification.hash.digest();
				final byte[] check = new byte[verification.hash.hashSize()];
				final int err = readAndHash(check);
				if (err < 0 || !Arrays.equals(check, digest))
					status = Status.WARNING_CHECKSUM;
			}
			if (!raw)
				skipRandomData();
			if (useMAC && version.compareTo(Version._202001) >= 0)
			{
				final byte[] digest = verification.mac.digest();
				final byte[] check = new byte[verification.mac.macSize()];
				final int err = readAndHash(check);
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
		catch (final InvalidKeyException | LimitReachedException e)
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
		catch (final Throwable t)
		{
			if (status == Status.RUNNING)
				status = Status.FAILED_OTHER;
			throw new CryptoProcessException(status, t);
		}
		finally
		{
			closeIgnoreException(source);
			closeIgnoreException(output);
		}
	}

	private Version readVersion() throws CryptoProcessException, IOException
	{
		final byte[] header = new byte[Long.SIZE / Byte.SIZE];
		for (int i = 0; i < HEADER.length; i++)
			source.read(header, 0, header.length);

		final Version v = Version.parseMagicNumber(Convert.longFromBytes(header), null);
		if (v == null)
			throw new CryptoProcessException(Status.FAILED_UNKNOWN_VERSION);

		if (v.compareTo(Version._201510) >= 0 && !raw)
			((EncryptedFileInputStream)source).initialiseECC();

		final byte[] b = new byte[source.read()];
		source.read(b);

		final String a = new String(b);
		cipher = a.substring(0, a.indexOf('/'));
		hash = a.substring(a.indexOf('/') + 1);
		if (hash.contains("/"))
		{
			mode = hash.substring(hash.indexOf('/') + 1);
			hash = hash.substring(0, hash.indexOf('/'));
			if (mode.contains("/"))
			{
				mac = mode.substring(mode.indexOf('/') + 1);
				mode = mode.substring(0, mode.indexOf('/'));
				if (mac.contains("/"))
				{
					final String kdf = mac.substring(mac.indexOf('/') + 1);
					mac = mac.substring(0, mac.indexOf('/'));
					/*
					 * tough tits if you used more than 2,147,483,647 iterations
					 * on your desktop (where libgcrypt uses an unsigned long)
					 */
					kdfIterations = (int)Long.parseLong(kdf, 0x10);
				}
			}
		}
		else
			mode = ModeFactory.CBC_MODE;

		return v;
	}

	private void readVerificationSum() throws CryptoProcessException, IOException
	{
		final byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
		readAndHash(buffer);
		final long x = Convert.longFromBytes(buffer);
		readAndHash(buffer);
		final long y = Convert.longFromBytes(buffer);
		readAndHash(buffer);
		final long z = Convert.longFromBytes(buffer);
		if ((x ^ y) != z)
			throw new CryptoProcessException(Status.FAILED_DECRYPTION);
	}

	private void readMetadata() throws CryptoProcessException, IOException
	{
		final byte[] c = new byte[Byte.SIZE / Byte.SIZE];
		readAndHash(c);
		for (int i = 0; i < (short)(Convert.byteFromBytes(c) & 0x00FF); i++)
		{
			final byte[] tv = new byte[Byte.SIZE / Byte.SIZE];
			readAndHash(tv);
			final Tag tag = Tag.fromValue((short)(Convert.byteFromBytes(tv) & 0x00FF));
			final byte[] l = new byte[Short.SIZE / Byte.SIZE];
			readAndHash(l);
			final int length = Convert.shortFromBytes(l);
			final byte[] v = new byte[length];
			readAndHash(v);
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
		if (name != null)
		{
			final DocumentFile documentFile = DocumentFile.fromTreeUri(this, path);
			contentResolver.takePersistableUriPermission(path, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
			final DocumentFile newFile = documentFile.createFile(null, name);
			output = contentResolver.openOutputStream(newFile.getUri());
		}
	}

	private void skipRandomData() throws IOException
	{
		final byte[] b = new byte[Byte.SIZE / Byte.SIZE];
		readAndHash(b);
		readAndHash(new byte[(short)(Convert.byteFromBytes(b) & 0x00FF)]);
	}

	private void decryptDirectory(final Uri uri) throws CryptoProcessException, IOException
	{
		final Map<String, DocumentFile> directories = new HashMap<>();

		contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION);
		final DocumentFile root = DocumentFile.fromTreeUri(this, uri);

		directories.put(SELF, root);

		for (total.offset = 0; total.offset < total.size && status == Status.RUNNING; total.offset++)
		{
			byte[] b = new byte[Byte.SIZE / Byte.SIZE];
			readAndHash(b);
			final FileType t = FileType.fromID(b[0]);
			b = new byte[Long.SIZE / Byte.SIZE];
			readAndHash(b);
			long l = Convert.longFromBytes(b);
			b = new byte[(int)l];
			readAndHash(b);
			String fullPath = new String(b);
			final Path path = new File(fullPath).toPath();
			DocumentFile parent = directories.get(path.getParent() != null ? path.getParent().toString() : SELF);

			switch (t)
			{
				case DIRECTORY:
					String p = "";
					for (final String d : fullPath.split("/"))
					{
						p += d;
						if (!directories.containsKey(p))
						{
							parent = parent.createDirectory(d);
							directories.put(p, parent);
						}
						p += '/';
					}
					break;
				case REGULAR:
					current.offset = 0;
					b = new byte[Long.SIZE / Byte.SIZE];
					readAndHash(b);
					final String filename = path.getFileName().toString();
					current.file = filename;
					current.size = Convert.longFromBytes(b);
					final DocumentFile newFile = parent.createFile(null, filename);
					output = contentResolver.openOutputStream(newFile.getUri());
					decryptFile();
					current.offset = current.size;
					output.close();
					output = null;
					break;
				case LINK:
				case SYMLINK:
					/*
					b = new byte[Long.SIZE / Byte.SIZE];
					readAndHash(b);
					l = Convert.longFromBytes(b);
					b = new byte[(int)l];
					readAndHash(b);
					final String ln = dir + File.separator + new String(b);
					if (t == FileType.LINK)
						Files.createLink(new File(nm).toPath(), new File(ln).toPath());
					else
						Files.createSymbolicLink(new File(nm).toPath(), new File(ln).toPath());
					*/
					break;
			}
		}
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
			verification.hash.update(buffer, 0, r);
			verification.mac.update(buffer, 0, r);
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
		verification.hash.update(b, 0, l);
		verification.mac.update(b, 0, l);
		return r;
	}
}
