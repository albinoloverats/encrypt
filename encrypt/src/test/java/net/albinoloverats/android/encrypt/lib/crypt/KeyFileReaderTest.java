/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2026, albinoloverats ~ Software Development
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
