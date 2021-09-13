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

package net.albinoloverats.android.encrypt.lib.crypt;

import android.app.Service;
import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.provider.DocumentsProvider;

import net.albinoloverats.android.encrypt.lib.io.EncryptedFileOutputStream;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZFormatException;
import org.tukaani.xz.XZOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import androidx.annotation.RequiresApi;
import androidx.documentfile.provider.DocumentFile;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.prng.LimitReachedException;
import gnu.crypto.util.PRNG;

public class Encrypt extends Crypto
{
	private String root = "";
	private final boolean follow = false;
	private final Map<Long, Path> inodes = new HashMap<>();

	@RequiresApi(api = Build.VERSION_CODES.Q)
	@Override
	public int onStartCommand(final Intent intent, final int flags, final int startId)
	{
		if (intent == null)
			return Service.START_REDELIVER_INTENT;
		final Uri source    = intent.getParcelableExtra("source");
		final Uri output    = intent.getParcelableExtra("output");
		cipher              = intent.getStringExtra("cipher");
		hash                = intent.getStringExtra("hash");
		mode                = intent.getStringExtra("mode");
		mac                 = intent.getStringExtra("mac");
		kdfIterations       = intent.getIntExtra("kdf_iterations", KDF_ITERATIONS_DEFAULT);
		key                 = intent.getByteArrayExtra("key");
		raw                 = intent.getBooleanExtra("raw", raw);
		compressed          = intent.getBooleanExtra("compress", compressed);
		follow_links        = intent.getBooleanExtra("follow", follow_links);
		version             = Version.parseMagicNumber(intent.getLongExtra("version", Version.CURRENT.magicNumber), Version.CURRENT);

		try
		{
			contentResolver = getContentResolver();
			final DocumentFile documentFile = DocumentFile.fromSingleUri(this, source);
			name = documentFile.getName();
			if (documentFile.isFile())
			{
				total.size = documentFile.length();
				this.source = contentResolver.openInputStream(source);
			}
			else if (documentFile.isDirectory())
			{
				directory = true;
				path = documentFile.getUri();
			}
			else
				status = Status.FAILED_IO;
			this.output = new EncryptedFileOutputStream(contentResolver.openOutputStream(output));
		}
		catch (final FileNotFoundException e)
		{
			status = Status.FAILED_IO;
		}

		if (raw)
			version = Version.CURRENT;

		switch (version)
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
				if (mode.equals(ModeFactory.CBC_MODE))
					version = Version._201311;
				break;
			case _201501:
			case _201510:
				break;
			case _201709:
				kdfIterations = KDF_ITERATIONS_201709;
				break;
			case _202001:
			case _202110:
			case CURRENT:
				if (kdfIterations == 0)
					kdfIterations = KDF_ITERATIONS_DEFAULT;
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
			boolean useMAC = true;
			if (version.compareTo(Version._201709) < 0)
				useMAC = false;
			/* we can use useMAC to indicate whether to use a proper key derivation function */
			verification = ((EncryptedFileOutputStream)output).initialiseEncryption(cipher, hash, mode, mac, kdfIterations, key, ivType, useMAC);

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
			output = compressed ? new XZOutputStream(output, opts) : output;

			verification.hash.reset();

			if (directory)
			{
				DocumentFile df = DocumentFile.fromSingleUri(this, path);
				String d = df.getName();
				do
				{
					root = File.separator + df.getName() + root;
				}
				while ((df = df.getParentFile()) != null);
				hashAndWrite(Convert.toBytes((byte)FileType.DIRECTORY.value));
				hashAndWrite(Convert.toBytes((long)d.length()));
				hashAndWrite(d.getBytes());
				total.offset = 1;
				encryptDirectory(root, path);
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
				hashAndWrite(verification.hash.digest());
				writeRandomData();
			}
			if (useMAC)
				hashAndWrite(verification.mac.digest());

			if (status == Status.RUNNING)
				status = Status.SUCCESS;
		}
		catch (final NoSuchAlgorithmException e)
		{
			status = Status.FAILED_UNKNOWN_ALGORITHM;
			throw new CryptoProcessException(Status.FAILED_UNKNOWN_ALGORITHM, e);
		}
		catch (final InvalidKeyException | LimitReachedException e)
		{
			status = Status.FAILED_KEY;
			throw new CryptoProcessException(Status.FAILED_KEY, e);
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
		catch (final Throwable t)
		{
			status = Status.FAILED_OTHER;
			throw new CryptoProcessException(Status.FAILED_OTHER, t);
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
		if (version.compareTo(Version._201510) >= 0 && !raw)
			((EncryptedFileOutputStream)output).initialiseECC();
		String algorithms = cipher + "/" + hash;
		if (version.compareTo(Version._201406) >= 0)
			algorithms = algorithms.concat("/" + mode);
		if (version.compareTo(Version._201709) >= 0)
			algorithms = algorithms.concat("/" + mac);
		if (version.compareTo(Version._202001) >= 0)
		{
			String kdf = String.format("%016x", (long)kdfIterations);
			algorithms = algorithms.concat("/" + kdf);
		}
		output.write((byte)algorithms.length());
		output.write(algorithms.getBytes());
	}

	private void writeVerificationSum() throws IOException
	{
		final byte[] buffer = new byte[Long.SIZE / Byte.SIZE];
		PRNG.nextBytes(buffer);
		final long x = Convert.longFromBytes(buffer);
		PRNG.nextBytes(buffer);
		final long y = Convert.longFromBytes(buffer);
		hashAndWrite(Convert.toBytes(x));
		hashAndWrite(Convert.toBytes(y));
		hashAndWrite(Convert.toBytes(x ^ y));
	}

	private void writeMetadata() throws IOException
	{
		byte meta = 3;
		if (!directory && name != null && version.compareTo(Version._201501) >= 0)
			meta++;
		hashAndWrite(Convert.toBytes(meta));

		if (directory) /* total size becomes number of entries */
		{
			String dir = "";
			DocumentFile df = DocumentFile.fromSingleUri(this, path);
			do
			{
				dir = File.separator + df.getName() + dir;
			}
			while ((df = df.getParentFile()) != null);
			total.size = countEntries(dir, path) + 1;
		}

		hashAndWrite(Convert.toBytes((byte)Tag.SIZE.value));
		hashAndWrite(Convert.toBytes((short)(Long.SIZE / Byte.SIZE)));
		hashAndWrite(Convert.toBytes(total.size));

		hashAndWrite(Convert.toBytes((byte)Tag.COMPRESSED.value));
		hashAndWrite(Convert.toBytes((short)(Byte.SIZE / Byte.SIZE)));
		hashAndWrite(Convert.toBytes(compressed));

		hashAndWrite(Convert.toBytes((byte)Tag.DIRECTORY.value));
		hashAndWrite(Convert.toBytes((short)(Byte.SIZE / Byte.SIZE)));
		hashAndWrite(Convert.toBytes(directory));

		if (!directory && name != null && version.compareTo(Version._201501) >= 0)
		{
			hashAndWrite(Convert.toBytes((byte)Tag.FILENAME.value));
			hashAndWrite(Convert.toBytes((short)name.length()));
			hashAndWrite(name.getBytes());
		}
	}

	private void writeRandomData() throws IOException
	{
		byte[] buffer = new byte[Short.SIZE / Byte.SIZE];
		PRNG.nextBytes(buffer);
		final short sr = (short)(Convert.shortFromBytes(buffer) & 0x00FF);
		buffer = new byte[sr];
		PRNG.nextBytes(buffer);
		hashAndWrite(Convert.toBytes((byte)sr));
		hashAndWrite(buffer);
	}

	private int countEntries(String dir, final Uri uri)
	{
		int c = 0;
//		final File[] files = new File(dir).listFiles();

		final DocumentFile documentFile = DocumentFile.fromSingleUri(this, uri);
		final DocumentFile[] files = documentFile.listFiles();
		if (files == null)
			return c;
		final LinkOption linkOptions = follow ? null : LinkOption.NOFOLLOW_LINKS;
		for (final DocumentFile file : files)
		{
			dir += File.separator + file.getName();
			final Path p = new File(dir).toPath();
//			final Path p = FileSystems.getDefault().getPath(file.getPath());
			if (Files.isDirectory(p, linkOptions))
				c += countEntries(dir, file.getUri());
			else if (Files.isRegularFile(p, linkOptions))
				c++;
			else if (Files.isSymbolicLink(p))
				c++;
		}
		return c;
	}

	private void encryptDirectory(final String dir, final Uri uri) throws IOException
	{
		final LinkOption linkOptions = follow ? null : LinkOption.NOFOLLOW_LINKS;
		final File[] files = new File(dir).listFiles();
		if (files == null)
			return;
		for (final File file : files)
		{
			if (status != Status.RUNNING)
				break;

			final FileType ft;
			final Path p = FileSystems.getDefault().getPath(file.getPath());
			Path ln = null;
			if (Files.isDirectory(p, linkOptions))
				ft = FileType.DIRECTORY;
			else if (Files.isRegularFile(p, linkOptions))
			{
				BasicFileAttributes bfa = Files.readAttributes(p, BasicFileAttributes.class, linkOptions);
				String s = bfa.fileKey().toString();
				Long inode = Long.parseLong(s.substring(s.indexOf("ino=") + 4, s.indexOf(")")));

				if (inodes.containsKey(inode))
				{
					ft = FileType.LINK;
					ln = inodes.get(inode);
				}
				else
				{
					ft = FileType.REGULAR;
					inodes.put(inode, p);
				}
			}
			else if (Files.isSymbolicLink(p))
			{
				ft = FileType.SYMLINK;
				ln = Files.readSymbolicLink(p);
			}
			else
				continue;

			hashAndWrite(Convert.toBytes((byte)ft.value));
			String name = dir + File.separator + file.getName();
			String nm = name.substring(root.length() + 1);
			hashAndWrite(Convert.toBytes((long)nm.length()));
			hashAndWrite(nm.getBytes());

			switch (ft)
			{
				case DIRECTORY:
					encryptDirectory(name, uri);
					break;
				case SYMLINK:
				case LINK:
					name = ln.toString();
					hashAndWrite(Convert.toBytes((long)name.length()));
					hashAndWrite(name.getBytes());
					break;
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
		verification.hash.update(b, 0, l);
		verification.mac.update(b, 0, l);
	}
}
