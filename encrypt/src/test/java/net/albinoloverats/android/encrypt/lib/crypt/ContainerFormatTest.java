package net.albinoloverats.android.encrypt.lib.crypt;

import gnu.crypto.mac.IMac;
import gnu.crypto.mac.HMac;
import gnu.crypto.hash.IMessageDigest;
import lombok.val;
import net.albinoloverats.android.encrypt.lib.io.HashMAC;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.FilterInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ContainerFormatTest
{
	private static final String CIPHER = "AES";
	private static final String HASH = "SHA256";
	private static final String MODE = "CBC";
	private static final String MAC = "HMAC_SHA256";
	private static final int KDF_ITERATIONS = 1024;

	@Test
	public void roundTripsVersionedHeadersAndEccInitialisation() throws Exception
	{
		for (final Version version : new Version[] { Version._201211, Version._201406, Version._201709, Version.CURRENT })
		{
			val bytes = new ByteArrayOutputStream();
			val writeEccCalls = new AtomicInteger();
			ContainerFormat.writeHeader(bytes, version, CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, false, writeEccCalls::incrementAndGet);

			val readEccCalls = new AtomicInteger();
			val header = ContainerFormat.readHeader(new ByteArrayInputStream(bytes.toByteArray()), false, readEccCalls::incrementAndGet);
			assertEquals(version.magicNumber, header.version().magicNumber);
			assertEquals(CIPHER, header.cipher());
			assertEquals(HASH, header.hash());
			assertEquals(version.compareTo(Version._201406) >= 0 ? MODE : "CBC", header.mode());
			assertEquals(version.compareTo(Version._201709) >= 0 ? MAC : null, header.mac());
			assertEquals(version.compareTo(Version._202001) >= 0 ? KDF_ITERATIONS : 0, header.kdfIterations());

			val expectedCalls = version.compareTo(Version._201510) >= 0 ? 1 : 0;
			assertEquals(expectedCalls, writeEccCalls.get());
			assertEquals(expectedCalls, readEccCalls.get());
		}
	}

	@Test
	public void rawHeadersDoNotEnableEcc() throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		val calls = new AtomicInteger();
		ContainerFormat.writeHeader(bytes, Version.CURRENT, CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, true, calls::incrementAndGet);
		ContainerFormat.readHeader(new ByteArrayInputStream(bytes.toByteArray()), true, calls::incrementAndGet);
		assertEquals(0, calls.get());
	}

	@Test
	public void rejectsUnknownAndTruncatedHeaders() throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		ContainerFormat.writeHeader(bytes, Version.CURRENT, CIPHER, HASH, MODE, MAC, KDF_ITERATIONS, true, () -> {});
		val invalidMagic = bytes.toByteArray();
		invalidMagic[0] ^= 1;
		try
		{
			ContainerFormat.readHeader(new ByteArrayInputStream(invalidMagic), true, () -> {});
			fail("Expected an invalid magic number to be rejected");
		}
		catch (final CryptoProcessException expected)
		{
			assertEquals(Status.FAILED_UNKNOWN_VERSION, expected.code);
		}

		try
		{
			ContainerFormat.readHeader(new ByteArrayInputStream(new byte[] { 1, 2, 3 }), true, () -> {});
			fail("Expected a truncated header to be rejected");
		}
		catch (final EOFException expected)
		{
			// Header fields must be complete before parsing.
		}
	}

	@Test
	public void writesAndReadsMetadataIncludingFilenameAndCompressionFlags() throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		val writerVerification = newVerification();
		val expected = new ContainerFormat.Metadata(123456L, 0, true, false, "report.dat");
		ContainerFormat.writeMetadata(bytes, writerVerification, Version.CURRENT, expected);
		val expectedHash = writerVerification.hash().digest();
		val expectedMac = writerVerification.mac().digest();

		val readerVerification = newVerification();
		val actual = ContainerFormat.readMetadata(new ByteArrayInputStream(bytes.toByteArray()), readerVerification);
		assertEquals(expected, actual);
		assertArrayEquals(expectedHash, readerVerification.hash().digest());
		assertArrayEquals(expectedMac, readerVerification.mac().digest());

		val corrupted = bytes.toByteArray();
		corrupted[corrupted.length - 1] ^= 1;
		val corruptedVerification = newVerification();
		ContainerFormat.readMetadata(new ByteArrayInputStream(corrupted), corruptedVerification);
		assertFalse(ContainerFormat.matches(corruptedVerification.mac().digest(), expectedMac));
	}

	@Test
	public void omitsFilenamesInLegacyMetadata() throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		ContainerFormat.writeMetadata(bytes, newVerification(), Version._201406,
			new ContainerFormat.Metadata(12, 0, false, false, "ignored.txt"));

		val metadata = ContainerFormat.readMetadata(new ByteArrayInputStream(bytes.toByteArray()), newVerification());
		assertEquals(12, metadata.totalSize());
		assertFalse(metadata.compressed());
		assertFalse(metadata.directory());
		assertEquals("decrypted", metadata.fileName());
	}

	@Test
	public void rejectsUnknownTagsAndTruncatedMetadata() throws Exception
	{
		val unknown = new ByteArrayOutputStream();
		unknown.write(1);
		unknown.write(255);
		unknown.write(new byte[] { 0, 0 });
		try
		{
			ContainerFormat.readMetadata(new ByteArrayInputStream(unknown.toByteArray()), newVerification());
			fail("Expected unknown metadata tag to be rejected");
		}
		catch (final CryptoProcessException expected)
		{
			assertEquals(Status.FAILED_UNKNOWN_TAG, expected.code);
		}

		val truncated = new ByteArrayOutputStream();
		ContainerFormat.writeMetadata(truncated, newVerification(), Version.CURRENT,
			new ContainerFormat.Metadata(12, 0, false, false, "name"));
		val shortReads = new FilterInputStream(new ByteArrayInputStream(truncated.toByteArray()))
		{
			@Override
			public int read(final byte[] b, final int off, final int len) throws IOException
			{
				return super.read(b, off, Math.min(2, len));
			}
		};
		assertEquals("name", ContainerFormat.readMetadata(shortReads, newVerification()).fileName());
		try
		{
			ContainerFormat.readMetadata(new ByteArrayInputStream(new byte[] { 1, 0 }), newVerification());
			fail("Expected incomplete metadata to be rejected");
		}
		catch (final EOFException expected)
		{
			// Truncated records must not be accepted silently.
		}
	}

	@Test
	public void verifiesXorChecksumAndDetectsCorruption() throws Exception
	{
		val bytes = new ByteArrayOutputStream();
		ContainerFormat.writeVerificationSum(bytes, newVerification());
		ContainerFormat.verifyVerificationSum(new ByteArrayInputStream(bytes.toByteArray()), newVerification());

		val corrupt = bytes.toByteArray();
		corrupt[0] ^= 1;
		try
		{
			ContainerFormat.verifyVerificationSum(new ByteArrayInputStream(corrupt), newVerification());
			fail("Expected checksum mismatch to fail");
		}
		catch (final CryptoProcessException expected)
		{
			assertEquals(Status.FAILED_DECRYPTION, expected.code);
		}
	}

	@Test
	public void roundTripsCompressedPayloadsAndComparesDigests() throws Exception
	{
		val payload = new byte[4096];
		for (int i = 0; i < payload.length; i++)
			payload[i] = (byte)(i % 13);

		val compressed = new ByteArrayOutputStream();
		try (val output = ContainerFormat.compress(compressed))
		{
			output.write(payload);
		}
		try (val input = ContainerFormat.decompress(new ByteArrayInputStream(compressed.toByteArray())))
		{
			assertArrayEquals(payload, input.readAllBytes());
		}

		assertTrue(ContainerFormat.matches(payload, payload.clone()));
		assertFalse(ContainerFormat.matches(payload, new byte[payload.length]));
	}

	private static HashMAC newVerification() throws Exception
	{
		val hash = CryptoUtils.getHashAlgorithm(HASH);
		val mac = CryptoUtils.getMacAlgorithm(MAC);
		val attributes = new HashMap<String, Object>();
		attributes.put(IMac.MAC_KEY_MATERIAL, new byte[64]);
		mac.init(attributes);
		return new HashMAC(hash, mac);
	}
}
