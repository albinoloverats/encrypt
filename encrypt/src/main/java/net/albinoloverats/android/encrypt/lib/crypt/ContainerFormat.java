package net.albinoloverats.android.encrypt.lib.crypt;

import gnu.crypto.util.PRNG;
import lombok.val;
import net.albinoloverats.android.encrypt.lib.io.HashMAC;
import net.albinoloverats.android.encrypt.lib.misc.Convert;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZInputStream;
import org.tukaani.xz.XZOutputStream;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public final class ContainerFormat
{
	private static final long[] MAGIC_HEADER = { 0x3697de5d96fca0faL, 0xc845c2fa95e2f52dL };
	private static final String DEFAULT_OUTPUT_FILENAME = "decrypted";

	private ContainerFormat()
	{
	}

	@FunctionalInterface
	public interface IoAction
	{
		void run() throws IOException;
	}

	public record Header(Version version, String cipher, String hash, String mode, String mac, int kdfIterations)
	{
	}

	public record Metadata(long totalSize, int blockSize, boolean compressed, boolean directory, String fileName)
	{
	}

	public static void writeHeader(final OutputStream output, final Version version, final String cipher, final String hash, final String mode, final String mac, final int kdfIterations, final boolean raw, final IoAction initialiseEcc) throws IOException
	{
		for (val value : MAGIC_HEADER)
			output.write(Convert.toBytes(value));
		output.write(Convert.toBytes(version.magicNumber));
		if (version.compareTo(Version._201510) >= 0 && !raw)
			initialiseEcc.run();

		var algorithms = cipher + "/" + hash;
		if (version.compareTo(Version._201406) >= 0)
			algorithms = algorithms.concat("/" + mode);
		if (version.compareTo(Version._201709) >= 0)
			algorithms = algorithms.concat("/" + mac);
		if (version.compareTo(Version._202001) >= 0)
			algorithms = algorithms.concat("/" + String.format("%016x", (long)kdfIterations));
		output.write(algorithms.length());
		output.write(algorithms.getBytes());
	}

	public static Header readHeader(final InputStream input, final boolean raw, final IoAction initialiseEcc) throws IOException, CryptoProcessException
	{
		val header = new byte[Long.SIZE / Byte.SIZE];
		for (int i = 0; i < MAGIC_HEADER.length; i++)
		{
			readFully(input, header);
			val magic = Convert.longFromBytes(header);
			if (magic != MAGIC_HEADER[i])
				throw new CryptoProcessException(Status.FAILED_UNKNOWN_VERSION);
		}
		readFully(input, header);
		val version = Version.parseMagicNumber(Convert.longFromBytes(header), null);
		if (version == null)
			throw new CryptoProcessException(Status.FAILED_UNKNOWN_VERSION);

		if (version.compareTo(Version._201510) >= 0 && !raw)
			initialiseEcc.run();

		val length = input.read();
		if (length < 0)
			throw new EOFException("Missing algorithm header");
		val algorithmBytes = new byte[length];
		readFully(input, algorithmBytes);
		val algorithms = new String(algorithmBytes).split("/", -1);
		if (algorithms.length < 2 || algorithms.length > 5)
			throw new IOException("Invalid algorithm header");

		val mode = algorithms.length > 2 ? algorithms[2] : "CBC";
		val mac = algorithms.length > 3 ? algorithms[3] : null;
		final int kdfIterations;
		try
		{
			kdfIterations = algorithms.length > 4 ? (int)Long.parseLong(algorithms[4], 16) : 0;
		}
		catch (final NumberFormatException e)
		{
			throw new IOException("Invalid KDF iteration count", e);
		}
		return new Header(version, algorithms[0], algorithms[1], mode, mac, kdfIterations);
	}

	public static void writeMetadata(final OutputStream output, final HashMAC verification, final Version version, final Metadata metadata) throws IOException
	{
		val count = !metadata.directory() && metadata.fileName() != null && version.compareTo(Version._201501) >= 0 ? 4 : 3;
		writeAndHash(output, verification, Convert.toBytes((byte)count));
		writeTag(output, verification, Tag.SIZE, Convert.toBytes(metadata.totalSize()));
		writeTag(output, verification, Tag.COMPRESSED, Convert.toBytes(metadata.compressed()));
		writeTag(output, verification, Tag.DIRECTORY, Convert.toBytes(metadata.directory()));
		if (count == 4)
			writeTag(output, verification, Tag.FILENAME, metadata.fileName().getBytes());
	}

	public static Metadata readMetadata(final InputStream input, final HashMAC verification) throws IOException, CryptoProcessException
	{
		val countBytes = new byte[1];
		readAndHash(input, verification, countBytes);
		val count = Convert.byteFromBytes(countBytes) & 0xFF;
		long totalSize = 0;
		int blockSize = 0;
		boolean compressed = false;
		boolean directory = false;
		String fileName = null;
		for (int i = 0; i < count; i++)
		{
			val tagBytes = new byte[1];
			readAndHash(input, verification, tagBytes);
			val tag = Tag.fromValue(Convert.byteFromBytes(tagBytes) & 0xFF);
			val lengthBytes = new byte[Short.SIZE / Byte.SIZE];
			readAndHash(input, verification, lengthBytes);
			val length = Convert.shortFromBytes(lengthBytes);
			if (length < 0)
				throw new IOException("Invalid metadata field length");
			val value = new byte[length];
			readAndHash(input, verification, value);
			switch (tag)
			{
				case SIZE -> totalSize = Convert.longFromBytes(value);
				case BLOCKED -> blockSize = (int)Convert.longFromBytes(value);
				case COMPRESSED -> compressed = Convert.booleanFromBytes(value);
				case DIRECTORY -> directory = Convert.booleanFromBytes(value);
				case FILENAME -> fileName = new String(value);
			}
		}
		if (!directory && fileName == null)
			fileName = DEFAULT_OUTPUT_FILENAME;
		return new Metadata(totalSize, blockSize, compressed, directory, fileName);
	}

	public static void writeVerificationSum(final OutputStream output, final HashMAC verification) throws IOException
	{
		val bytes = new byte[Long.SIZE / Byte.SIZE];
		PRNG.nextBytes(bytes);
		val x = Convert.longFromBytes(bytes);
		PRNG.nextBytes(bytes);
		val y = Convert.longFromBytes(bytes);
		writeAndHash(output, verification, Convert.toBytes(x));
		writeAndHash(output, verification, Convert.toBytes(y));
		writeAndHash(output, verification, Convert.toBytes(x ^ y));
	}

	public static void verifyVerificationSum(final InputStream input, final HashMAC verification) throws IOException, CryptoProcessException
	{
		val bytes = new byte[Long.SIZE / Byte.SIZE];
		readAndHash(input, verification, bytes);
		val x = Convert.longFromBytes(bytes);
		readAndHash(input, verification, bytes);
		val y = Convert.longFromBytes(bytes);
		readAndHash(input, verification, bytes);
		val check = Convert.longFromBytes(bytes);
		if ((x ^ y) != check)
			throw new CryptoProcessException(Status.FAILED_DECRYPTION);
	}

	public static void writeRandomData(final OutputStream output, final HashMAC verification) throws IOException
	{
		val lengthBytes = new byte[Short.SIZE / Byte.SIZE];
		PRNG.nextBytes(lengthBytes);
		val length = Convert.shortFromBytes(lengthBytes) & 0xFF;
		val data = new byte[length];
		PRNG.nextBytes(data);
		writeAndHash(output, verification, Convert.toBytes((byte)length));
		writeAndHash(output, verification, data);
	}

	public static void skipRandomData(final InputStream input, final HashMAC verification) throws IOException
	{
		val length = new byte[1];
		readAndHash(input, verification, length);
		readAndHash(input, verification, new byte[Convert.byteFromBytes(length) & 0xFF]);
	}

	public static boolean matches(final byte[] actual, final byte[] expected)
	{
		return Arrays.equals(actual, expected);
	}

	public static OutputStream compress(final OutputStream output) throws IOException
	{
		val options = new LZMA2Options(LZMA2Options.PRESET_MIN);
		options.setDictSize(LZMA2Options.DICT_SIZE_MIN);
		return new XZOutputStream(output, options);
	}

	public static InputStream decompress(final InputStream input) throws IOException
	{
		return new XZInputStream(input);
	}

	private static void writeTag(final OutputStream output, final HashMAC verification, final Tag tag, final byte[] value) throws IOException
	{
		writeAndHash(output, verification, Convert.toBytes((byte)tag.value));
		writeAndHash(output, verification, Convert.toBytes((short)value.length));
		writeAndHash(output, verification, value);
	}

	private static void writeAndHash(final OutputStream output, final HashMAC verification, final byte[] bytes) throws IOException
	{
		output.write(bytes);
		verification.hash().update(bytes, 0, bytes.length);
		verification.mac().update(bytes, 0, bytes.length);
	}

	private static void readAndHash(final InputStream input, final HashMAC verification, final byte[] bytes) throws IOException
	{
		readFully(input, bytes);
		verification.hash().update(bytes, 0, bytes.length);
		verification.mac().update(bytes, 0, bytes.length);
	}

	private static void readFully(final InputStream input, final byte[] bytes) throws IOException
	{
		int offset = 0;
		while (offset < bytes.length)
		{
			val count = input.read(bytes, offset, bytes.length - offset);
			if (count < 0)
				throw new EOFException("Truncated container data");
			if (count == 0)
				continue;
			offset += count;
		}
	}
}
