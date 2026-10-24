package net.albinoloverats.android.encrypt.lib.io;

import net.albinoloverats.android.encrypt.lib.crypt.XIV;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class EncryptedFileStreamTest
{
	private static final String CIPHER = "AES";
	private static final String HASH = "SHA256";
	private static final String MODE = "CBC";
	private static final String MAC = "HMAC_SHA256";
	private static final int KDF_ITERATIONS = 1000;
	private static final byte[] KEY = "stream test key".getBytes(StandardCharsets.UTF_8);

	@Test
	public void encryptsAndDecryptsWithDeterministicIv() throws Exception
	{
		assertRoundTrip(XIV.SIMPLE, false);
	}

	@Test
	public void encryptsAndDecryptsWithRandomIvAndDerivedKey() throws Exception
	{
		assertRoundTrip(XIV.RANDOM, true);
	}

	@Test
	public void passesThroughDataBeforeEncryptionIsInitialised() throws Exception
	{
		final byte[] original = data(64);
		final ByteArrayOutputStream encoded = new ByteArrayOutputStream();
		final EncryptedFileOutputStream output = new EncryptedFileOutputStream(encoded);
		output.write(original);
		output.close();
		assertArrayEquals(original, encoded.toByteArray());

		final EncryptedFileInputStream input = new EncryptedFileInputStream(new ByteArrayInputStream(original));
		final byte[] decoded = new byte[original.length];
		assertEquals(original.length, input.read(decoded));
		assertArrayEquals(original, decoded);
		input.close();
	}

	@Test
	public void readsCipherBlockBoundariesAndStopsAtEndOfCiphertext() throws Exception
	{
		for (final int length : new int[] { 0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257 })
		{
			final byte[] original = data(length);
			final byte[] encrypted = encrypt(original);
			final EncryptedFileInputStream input = decrypt(encrypted, KEY);
			assertEquals("zero-length read at length " + length, 0, input.read(new byte[0]));

			final byte[] decoded = readToEnd(input);
			final int encryptedLength = (length / 16 + 1) * 16;
			assertEquals("decrypted block length " + length, encryptedLength, decoded.length);
			assertArrayEquals("plaintext prefix " + length, original, Arrays.copyOf(decoded, length));
			assertEquals("EOF after ciphertext " + length, -1, input.read());
			assertEquals("stable EOF " + length, -1, input.read());
			input.close();
		}
	}

	@Test
	public void rejectsTruncatedEncryptedFrames() throws Exception
	{
		final byte[] encrypted = encrypt(data(64));
		final byte[] truncated = Arrays.copyOf(encrypted, encrypted.length - 1);
		final EncryptedFileInputStream input = decrypt(truncated, KEY);
		try
		{
			readToEnd(input);
			throw new AssertionError("Expected truncated encrypted input to fail");
		}
		catch (final EOFException expected)
		{
			// The ECC frame declared bytes that were not present in the source.
		}
		finally
		{
			input.close();
		}
	}

	@Test
	public void validatesReadSliceArguments() throws Exception
	{
		final EncryptedFileInputStream input = decrypt(encrypt(data(16)), KEY);
		assertThrows(IndexOutOfBoundsException.class, () -> input.read(new byte[4], -1, 1));
		assertThrows(IndexOutOfBoundsException.class, () -> input.read(new byte[4], 0, 5));
		assertThrows(IndexOutOfBoundsException.class, () -> input.read(new byte[4], 2, Integer.MAX_VALUE));
		input.close();
	}

	private static void assertRoundTrip(final XIV ivType, final boolean useKdf) throws Exception
	{
		final byte[] original = data(64);
		final ByteArrayOutputStream encoded = new ByteArrayOutputStream();
		final EncryptedFileOutputStream output = new EncryptedFileOutputStream(encoded);
		output.initialiseEncryption(CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, KEY, ivType, useKdf);
		output.initialiseECC();
		output.write(original, 0, 7);
		output.write(original, 7, original.length - 7);
		output.close();

		final EncryptedFileInputStream input = new EncryptedFileInputStream(new ByteArrayInputStream(encoded.toByteArray()));
		input.initialiseDecryption(CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, KEY, ivType, useKdf);
		input.initialiseECC();
		final byte[] decoded = new byte[original.length + 8];
		assertEquals(original.length, input.read(decoded, 4, original.length));
		assertArrayEquals(original, Arrays.copyOfRange(decoded, 4, decoded.length - 4));
		input.close();
	}

	private static byte[] encrypt(final byte[] original) throws Exception
	{
		final ByteArrayOutputStream encoded = new ByteArrayOutputStream();
		final EncryptedFileOutputStream output = new EncryptedFileOutputStream(encoded);
		output.initialiseEncryption(CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, KEY, XIV.SIMPLE, false);
		output.initialiseECC();
		output.write(original);
		output.close();
		return encoded.toByteArray();
	}

	private static EncryptedFileInputStream decrypt(final byte[] encoded, final byte[] key) throws Exception
	{
		final EncryptedFileInputStream input = new EncryptedFileInputStream(new ByteArrayInputStream(encoded));
		input.initialiseDecryption(CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, key, XIV.SIMPLE, false);
		input.initialiseECC();
		return input;
	}

	private static byte[] readToEnd(final EncryptedFileInputStream input) throws Exception
	{
		final ByteArrayOutputStream decoded = new ByteArrayOutputStream();
		final byte[] buffer = new byte[11];
		int count;
		while ((count = input.read(buffer)) >= 0)
			decoded.write(buffer, 0, count);
		return decoded.toByteArray();
	}

	private static byte[] data(final int length)
	{
		final byte[] data = new byte[length];
		for (int i = 0; i < length; i++)
			data[i] = (byte)(i * 17 + 3);
		return data;
	}
}
