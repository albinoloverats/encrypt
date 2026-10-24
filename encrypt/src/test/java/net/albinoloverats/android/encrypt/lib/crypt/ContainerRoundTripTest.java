package net.albinoloverats.android.encrypt.lib.crypt;

import lombok.val;
import net.albinoloverats.android.encrypt.lib.io.EncryptedFileInputStream;
import net.albinoloverats.android.encrypt.lib.io.EncryptedFileOutputStream;
import net.albinoloverats.android.encrypt.lib.io.HashMAC;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ContainerRoundTripTest
{
	private static final String CIPHER = "AES";
	private static final String HASH = "SHA256";
	private static final String MODE = "CBC";
	private static final String MAC = "HMAC_SHA256";
	private static final int KDF_ITERATIONS = 1024;
	private static final byte[] KEY = "end-to-end container key".getBytes(StandardCharsets.UTF_8);

	@Test
	public void validatesAnEntireEncryptedContainer() throws Exception
	{
		val plaintext = data(93);
		val container = writeContainer(plaintext, KEY, false);
		val result = readContainer(container, KEY);
		assertArrayEquals(plaintext, result.plaintext());
		assertTrue(result.digestValid());
		assertTrue(result.macValid());
	}

	@Test
	public void rejectsWrongKeysAndDetectsMacTampering() throws Exception
	{
		val plaintext = data(93);
		val container = writeContainer(plaintext, KEY, false);
		try
		{
			readContainer(container, "incorrect key".getBytes(StandardCharsets.UTF_8));
			fail("Expected wrong key to fail the container verification checksum");
		}
		catch (final CryptoProcessException expected)
		{
			assertEquals(Status.FAILED_DECRYPTION, expected.code);
		}

		val damagedMac = writeContainer(plaintext, KEY, true);
		val result = readContainer(damagedMac, KEY);
		assertArrayEquals(plaintext, result.plaintext());
		assertTrue(result.digestValid());
		assertFalse(result.macValid());
	}

	private static byte[] writeContainer(final byte[] plaintext, final byte[] key, final boolean corruptMac) throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		val output = new EncryptedFileOutputStream(bytes);
		ContainerFormat.writeHeader(output, Version.CURRENT, CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, false, output::initialiseECC);
		val verification = output.initialiseEncryption(CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, key, XIV.RANDOM, true);

		ContainerFormat.writeRandomData(output, verification);
		ContainerFormat.writeVerificationSum(output, verification);
		ContainerFormat.writeRandomData(output, verification);
		ContainerFormat.writeMetadata(output, verification, Version.CURRENT,
			new ContainerFormat.Metadata(plaintext.length, 0, false, false, "payload.bin"));
		ContainerFormat.writeRandomData(output, verification);

		verification.hash().reset();
		output.write(plaintext);
		verification.hash().update(plaintext, 0, plaintext.length);
		verification.mac().update(plaintext, 0, plaintext.length);
		output.write(verification.hash().digest());
		ContainerFormat.writeRandomData(output, verification);
		val mac = verification.mac().digest();
		if (corruptMac)
			mac[0] ^= 1;
		output.write(mac);
		output.close();
		return bytes.toByteArray();
	}

	private static ContainerResult readContainer(final byte[] bytes, final byte[] key) throws Exception
	{
		val input = new EncryptedFileInputStream(new ByteArrayInputStream(bytes));
		try
		{
			val header = ContainerFormat.readHeader(input, false, input::initialiseECC);
			val verification = input.initialiseDecryption(header.cipher(), header.hash(), header.mode(), header.mac(),
				header.kdfIterations(), key, XIV.RANDOM, true);

			ContainerFormat.skipRandomData(input, verification);
			ContainerFormat.verifyVerificationSum(input, verification);
			ContainerFormat.skipRandomData(input, verification);
			val metadata = ContainerFormat.readMetadata(input, verification);
			ContainerFormat.skipRandomData(input, verification);

			verification.hash().reset();
			val plaintext = new byte[(int)metadata.totalSize()];
			readFully(input, plaintext);
			verification.hash().update(plaintext, 0, plaintext.length);
			verification.mac().update(plaintext, 0, plaintext.length);

			val expectedDigest = new byte[verification.hash().hashSize()];
			readFully(input, expectedDigest);
			val digestValid = ContainerFormat.matches(verification.hash().digest(), expectedDigest);

			ContainerFormat.skipRandomData(input, verification);
			val expectedMac = new byte[verification.mac().macSize()];
			readFully(input, expectedMac);
			val macValid = ContainerFormat.matches(verification.mac().digest(), expectedMac);
			return new ContainerResult(plaintext, digestValid, macValid);
		}
		finally
		{
			input.close();
		}
	}

	private static void readFully(final EncryptedFileInputStream input, final byte[] bytes) throws IOException
	{
		int offset = 0;
		while (offset < bytes.length)
		{
			val count = input.read(bytes, offset, bytes.length - offset);
			if (count < 0)
				throw new EOFException("Truncated container");
			offset += count;
		}
	}

	private static byte[] data(final int length)
	{
		val bytes = new byte[length];
		for (int i = 0; i < length; i++)
			bytes[i] = (byte)(i * 29 + 11);
		return bytes;
	}

	private record ContainerResult(byte[] plaintext, boolean digestValid, boolean macValid)
	{
	}
}
