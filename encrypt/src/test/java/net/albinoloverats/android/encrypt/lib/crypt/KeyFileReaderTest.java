package net.albinoloverats.android.encrypt.lib.crypt;

import lombok.val;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

public class KeyFileReaderTest
{
	@Test
	public void readsUntilEndEvenWhenStreamReturnsShortReads() throws Exception
	{
		val expected = new byte[] { 1, 2, 3, 4, 5 };
		val input = new ByteArrayInputStream(expected)
		{
			@Override
			public int read(final byte[] bytes, final int offset, final int length)
			{
				return super.read(bytes, offset, Math.min(length, 2));
			}
		};

		assertArrayEquals(expected, KeyFileReader.read(input));
	}

	@Test
	public void handlesZeroLengthReadsWithoutStoppingEarly() throws Exception
	{
		val input = new InputStream()
		{
			private final byte[] bytes = { 7, 8, 9 };
			private int offset;
			private boolean returnZero = true;

			@Override
			public int read(final byte[] target, final int start, final int length)
			{
				if (returnZero)
				{
					returnZero = false;
					return 0;
				}
				if (offset == bytes.length)
					return -1;
				val count = Math.min(length, bytes.length - offset);
				System.arraycopy(bytes, offset, target, start, count);
				offset += count;
				return count;
			}

			@Override
			public int read()
			{
				return offset == bytes.length ? -1 : bytes[offset++] & 0xFF;
			}
		};

		assertArrayEquals(new byte[] { 7, 8, 9 }, KeyFileReader.read(input));
	}

	@Test
	public void rejectsEmptyKeyFiles() throws Exception
	{
		assertThrows(IOException.class, () -> KeyFileReader.read(new ByteArrayInputStream(new byte[0])));
	}

	@Test
	public void propagatesReadFailures() throws Exception
	{
		val input = new InputStream()
		{
			@Override
			public int read() throws IOException
			{
				throw new IOException("read failed");
			}
		};

		assertThrows(IOException.class, () -> KeyFileReader.read(input));
	}
}
