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

package net.albinoloverats.android.encrypt.lib.crypt;

import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import androidx.documentfile.provider.DocumentFile;
import gnu.crypto.mode.ModeFactory;
import gnu.crypto.prng.LimitReachedException;
import lombok.val;
import net.albinoloverats.android.encrypt.lib.io.EncryptedFileOutputStream;
import net.albinoloverats.android.encrypt.lib.misc.Convert;
import org.tukaani.xz.XZFormatException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static net.albinoloverats.android.encrypt.lib.IntentKey.CIPHER;
import static net.albinoloverats.android.encrypt.lib.IntentKey.COMPRESS;
import static net.albinoloverats.android.encrypt.lib.IntentKey.ENCRYPTING;
import static net.albinoloverats.android.encrypt.lib.IntentKey.FOLLOW;
import static net.albinoloverats.android.encrypt.lib.IntentKey.HASH;
import static net.albinoloverats.android.encrypt.lib.IntentKey.KDF_ITERATIONS;
import static net.albinoloverats.android.encrypt.lib.IntentKey.MAC;
import static net.albinoloverats.android.encrypt.lib.IntentKey.MODE;
import static net.albinoloverats.android.encrypt.lib.IntentKey.VERSION;

public class Encrypt extends Crypto
{
	private List<Uri> fakeDir = null;

	@Override
	public int onStartCommand(final Intent intent, final int flags, final int startId)
	{
		if (intent == null)
			return Service.START_REDELIVER_INTENT;

		preInit();

		val source = getSource(intent);
		val output = getOutput(intent);
		cipher = intent.getStringExtra(CIPHER.toString());
		hash = intent.getStringExtra(HASH.toString());
		mode = intent.getStringExtra(MODE.toString());
		mac = intent.getStringExtra(MAC.toString());
		kdfIterations = intent.getIntExtra(KDF_ITERATIONS.toString(), KDF_ITERATIONS_DEFAULT);

		compressed = intent.getBooleanExtra(COMPRESS.toString(), compressed);
		follow_links = intent.getBooleanExtra(FOLLOW.toString(), follow_links);
		version = Version.parseMagicNumber(intent.getLongExtra(VERSION.toString(), Version.CURRENT.magicNumber), Version.CURRENT);

		try
		{
			contentResolver = getContentResolver();

			if (source.size() == 1)
			{
				val uri = source.get(0);
				val documentFile = DocumentFile.fromSingleUri(this, uri);
				if (documentFile == null)
					throw new FileNotFoundException("Could not get file from URI");
				name = documentFile.getName();
				total.size = documentFile.length();
				this.source = contentResolver.openInputStream(uri);
			}
			else
			{
				directory = true;
				fakeDir = source;
			}
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
			case _202201:
			case _202401:
			case _202505:
			case CURRENT:
				if (kdfIterations == 0)
					kdfIterations = KDF_ITERATIONS_DEFAULT;
				break;
		}

		intent.putExtra(ENCRYPTING.toString(), true);
		return super.onStartCommand(intent, flags, startId);
	}

	@Override
	protected void process() throws CryptoProcessException
	{
		try
		{
			status = Status.RUNNING;

			if (!raw)
				ContainerFormat.writeHeader(output, version, cipher, hash, mode, mac, kdfIterations, raw, () -> ((EncryptedFileOutputStream)output).initialiseECC());

			var extraRandom = true;
			var ivType = XIV.RANDOM;
			if (version.compareTo(Version._201211) <= 0)
			{
				ivType = XIV.SIMPLE;
				extraRandom = false;
			}
			if (version.compareTo(Version._201110) <= 0)
				ivType = XIV.BROKEN;
			val useMAC = version.compareTo(Version._201709) >= 0;
			/* we can use useMAC to indicate whether to use a proper key derivation function */
			verification = ((EncryptedFileOutputStream)output).initialiseEncryption(cipher, hash, mode, mac, kdfIterations, key, ivType, useMAC);

			if (!raw)
			{
				if (extraRandom)
					ContainerFormat.writeRandomData(output, verification);
				ContainerFormat.writeVerificationSum(output, verification);
				ContainerFormat.writeRandomData(output, verification);
			}
			if (directory)
				total.size = fakeDir.size() + 1;
			ContainerFormat.writeMetadata(output, verification, version, new ContainerFormat.Metadata(total.size, blockSize, compressed, directory, name));

			if (extraRandom && !raw)
				ContainerFormat.writeRandomData(output, verification);

			output = compressed ? ContainerFormat.compress(output) : output;

			verification.hash().reset();

			if (directory)
			{
				hashAndWrite(Convert.toBytes((byte)FileType.DIRECTORY.value));
				hashAndWrite(Convert.toBytes(1L));
				hashAndWrite(new byte[] { '.' });
				total.offset = 1;
				for (var uri : fakeDir)
				{
					if (status != Status.RUNNING)
						break;
					val documentFile = DocumentFile.fromSingleUri(this, uri);
					if (documentFile == null)
					{
						status = Status.FAILED_IO;
						break;
					}
					if (!documentFile.isFile())
						continue;
					val name = documentFile.getName();
					current.file = name != null ? name : "";
					source = contentResolver.openInputStream(uri);

					hashAndWrite(Convert.toBytes((byte)FileType.REGULAR.value));
					hashAndWrite(Convert.toBytes((long)current.file.length()));
					hashAndWrite(current.file.getBytes());

					current.offset = 0;
					current.size = documentFile.length();
					hashAndWrite(Convert.toBytes(current.size));
					encryptFile();
					current.offset = current.size;
					source.close();
					source = null;
					total.offset++;
				}
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
				hashAndWrite(verification.hash().digest());
				ContainerFormat.writeRandomData(output, verification);
			}
			if (useMAC)
				hashAndWrite(verification.mac().digest());

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
			closeIgnoreEverything(source);
			closeIgnoreEverything(output);
		}
	}

	private void encryptFile() throws IOException
	{
		val buffer = new byte[BLOCK_SIZE];
		for (current.offset = 0; current.offset < current.size && status == Status.RUNNING; current.offset += BLOCK_SIZE)
			hashAndWrite(buffer, source.read(buffer, 0, BLOCK_SIZE));
	}

	private void hashAndWrite(final byte[] b) throws IOException
	{
		hashAndWrite(b, b.length);
	}

	private void hashAndWrite(final byte[] b, final int l) throws IOException
	{
		output.write(b, 0, l);
		verification.hash().update(b, 0, l);
		verification.mac().update(b, 0, l);
	}
}
