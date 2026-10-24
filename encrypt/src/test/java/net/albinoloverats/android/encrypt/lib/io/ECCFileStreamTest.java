package net.albinoloverats.android.encrypt.lib.io;

import lombok.val;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ECCFileStreamTest
{
	@Test
	public void passesThroughDataWhenEccIsNotInitialised() throws IOException
	{
		val data = bytes(32);
		val encoded = new ByteArrayOutputStream();
		val output = new ECCFileOutputStream(encoded);
		output.write(data);
		output.close();
		assertArrayEquals(data, encoded.toByteArray());

		val input = new ECCFileInputStream(new ByteArrayInputStream(data));
		assertArrayEquals(data, readToEnd(input));
		input.close();
	}

	@Test
	public void roundTripsEmptyAndBoundaryPayloads() throws IOException
	{
		for (val length : new int[] { 0, 1, 248, 249, 250, 498, 499, 1000 })
		{
			val original = bytes(length);
			val encoded = new ByteArrayOutputStream();
			val output = new ECCFileOutputStream(encoded);
			output.initialise();
			output.write(original);
			output.close();

			val input = new ECCFileInputStream(new ByteArrayInputStream(encoded.toByteArray()));
			input.initialise();
			assertArrayEquals("payload length " + length, original, readToEnd(input));
			input.close();
		}
	}

	@Test
	public void supportsSingleByteAndSegmentedReads() throws IOException
	{
		val original = bytes(600);
		val encoded = new ByteArrayOutputStream();
		val output = new ECCFileOutputStream(encoded);
		output.initialise();
		output.write(original);
		output.close();

		val input = new ECCFileInputStream(new ByteArrayInputStream(encoded.toByteArray()));
		input.initialise();
		val decoded = new ByteArrayOutputStream();
		for (int i = 0; i < original.length; i++)
		{
			val value = input.read();
			assertEquals(original[i] & 0xFF, value);
			decoded.write(value);
		}
		assertArrayEquals(original, decoded.toByteArray());
		input.close();
	}

	@Test
	public void readsIntoSlicesAndReturnsEndOfStream() throws IOException
	{
		val original = bytes(257);
		val encoded = new ByteArrayOutputStream();
		val output = new ECCFileOutputStream(encoded);
		output.initialise();
		output.write(original);
		output.close();

		val input = new ECCFileInputStream(new ByteArrayInputStream(encoded.toByteArray()));
		input.initialise();
		val destination = new byte[original.length + 8];
		assertEquals(original.length, input.read(destination, 4, original.length));
		assertEquals(-1, input.read());
		assertArrayEquals(original, java.util.Arrays.copyOfRange(destination, 4, destination.length - 4));
		input.close();
	}

	@Test
	public void handlesShortReadsFromTheEncodedSource() throws IOException
	{
		val original = bytes(700);
		val encoded = encode(original);
		val shortReads = new FilterInputStream(new ByteArrayInputStream(encoded))
		{
			@Override
			public int read(final byte[] b, final int off, final int len) throws IOException
			{
				return super.read(b, off, Math.min(len, 7));
			}
		};
		val input = new ECCFileInputStream(shortReads);
		input.initialise();
		assertArrayEquals(original, readToEnd(input));
		input.close();
	}

	@Test
	public void rejectsTruncatedEncodedBlocks() throws IOException
	{
		val encoded = encode(bytes(1));
		val input = new ECCFileInputStream(new ByteArrayInputStream(java.util.Arrays.copyOf(encoded, encoded.length - 1)));
		input.initialise();
		try
		{
			input.read();
			fail("Expected a truncated ECC block to be rejected");
		}
		catch (final EOFException expected)
		{
			// Expected: a frame length was present, but its encoded block was incomplete.
		}
		finally
		{
			input.close();
		}
	}

	@Test
	public void correctsSingleByteErrorsInEncodedBlocks() throws IOException
	{
		val original = bytes(128);
		val encoded = encode(original);
		encoded[37] ^= (byte)0xA5;
		val input = new ECCFileInputStream(new ByteArrayInputStream(encoded));
		input.initialise();
		assertArrayEquals(original, readToEnd(input));
		assertEquals(1, input.getDecodeError());
		input.close();
	}

	@Test
	public void rejectsUncorrectableBlocks() throws IOException
	{
		val encoded = encode(bytes(128));
		for (int i = 5; i < 9; i++)
			encoded[i] ^= (byte)(0x31 + i);

		val input = new ECCFileInputStream(new ByteArrayInputStream(encoded));
		input.initialise();
		try
		{
			readToEnd(input);
			fail("Expected an uncorrectable ECC block to fail");
		}
		catch (final IOException expected)
		{
			// The decoder must report an uncorrectable codeword rather than return a negative byte count.
		}
		finally
		{
			input.close();
		}
	}

	private static byte[] bytes(final int length)
	{
		val data = new byte[length];
		for (int i = 0; i < length; i++)
			data[i] = (byte)(i * 31 + 7);
		return data;
	}

	private static byte[] encode(final byte[] data) throws IOException
	{
		val encoded = new ByteArrayOutputStream();
		val output = new ECCFileOutputStream(encoded);
		output.initialise();
		output.write(data);
		output.close();
		return encoded.toByteArray();
	}

	private static byte[] readToEnd(final ECCFileInputStream input) throws IOException
	{
		val decoded = new ByteArrayOutputStream();
		int value;
		while ((value = input.read()) >= 0)
			decoded.write(value);
		return decoded.toByteArray();
	}
}
