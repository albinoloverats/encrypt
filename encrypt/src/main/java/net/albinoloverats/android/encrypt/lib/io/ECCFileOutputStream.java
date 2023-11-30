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

package net.albinoloverats.android.encrypt.lib.io;

import net.albinoloverats.android.encrypt.lib.misc.Convert;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;

public class ECCFileOutputStream extends ECCFileStream
{
	private final OutputStream outputStream;

	public ECCFileOutputStream(final OutputStream stream) throws FileNotFoundException
	{
		outputStream = stream;
		source = new byte[PAYLOAD];
		offset = new int[] { 0, 0 };
	}

	public void close() throws IOException
	{
		if (initialised)
		{
			final int[] remainder = { 0, PAYLOAD - offset[0] };
			final byte[] x = new byte[remainder[1]];
			System.arraycopy(x, 0, source, offset[0], remainder[1]);
			outputStream.write(offset[0]);
			outputStream.write(encode());
		}
		outputStream.flush();
		outputStream.close();
	}

	public void write(final byte[] bytes) throws IOException
	{
		if (!initialised)
		{
			outputStream.write(bytes);
			return;
		}

		final int[] remainder = { bytes.length, PAYLOAD - offset[0] };
		offset[1] = 0;
		while (remainder[0] > 0)
		{
			if (remainder[0] < remainder[1])
			{
				System.arraycopy(bytes, offset[1], source, offset[0], remainder[0]);
				offset[0] += remainder[0];
				return;
			}
			System.arraycopy(bytes, offset[1], source, offset[0], remainder[1]);
			outputStream.write(PAYLOAD);
			outputStream.write(encode());
			offset[0] = 0;
			source = new byte[PAYLOAD];
			offset[1] += remainder[1];
			remainder[0] -= remainder[1];
			remainder[1] = PAYLOAD - offset[0];
		}
	}

	public void write(final byte[] b, final int off, final int len) throws IOException
	{
		final byte[] bytes = new byte[len];
		System.arraycopy(b, off, bytes, 0, len);
		write(bytes);
	}

	public void write(final int b) throws IOException
	{
		write(Convert.toBytes((byte)(b & 0x000000FF)));
	}

	private byte[] encode()
	{
		final byte[] encoded = new byte[CAPACITY];
		byte[] r = new byte[OFFSET];
		for (int i = 0; i < PAYLOAD; i++)
		{
			encoded[CAPACITY - 1 - i] = source[i];
			byte rtmp = (byte)add(source[i], r[5]);
			for (int j = 5; j > 0; j--)
				r[j] = (byte)add(mul(rtmp, GEE[j]), r[j - 1]);
			r[0] = (byte)mul(rtmp, GEE[0]);
		}
		for (int i = 0; i < OFFSET; i++)
			encoded[i] = r[i];
		reverse(encoded, CAPACITY);
		return encoded;
	}
}
