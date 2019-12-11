/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2020, albinoloverats ~ Software Development
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.channels.FileChannel;

public class ECCFileInputStream extends ECCFileStream
{
	private final FileInputStream fileInputStream;

	private int decodeError;

	public ECCFileInputStream(final File file) throws FileNotFoundException
	{
		fileInputStream = new FileInputStream(file);
		source = new byte[CAPACITY];
		offset = new int[] { 0, 0, 0};
	}

	public int available() throws IOException
	{
		if (!initialised)
			return fileInputStream.available();
		return offset[0];
	}

	public void close() throws IOException
	{
		fileInputStream.close();
	}

	public FileChannel getChannel()
	{
		return fileInputStream.getChannel();
	}

	public int read() throws IOException
	{
		final byte[] b = new byte[Integer.SIZE / Byte.SIZE];
		int err = read(b, 3, 1);
		return err < 0 ? err : Convert.intFromBytes(b);
	}

	public int read(final byte[] bytes) throws IOException
	{
		int err = 0;
		if (!initialised)
			return fileInputStream.read(bytes);

		offset[1] = bytes.length;
		offset[2] = 0;
		while (true)
		{
			if (offset[0] >= offset[1])
			{
				System.arraycopy(source, 0, bytes, offset[2], offset[1]);
				offset[0] -= offset[1];
				final byte[] x = new byte[PAYLOAD];
				System.arraycopy(source, offset[1], x, 0, offset[0]);
				source = new byte[PAYLOAD];
				System.arraycopy(x, 0, source, 0, offset[0]);
				return err < 0 ? err : offset[1] + offset[2];
			}
			System.arraycopy(source, 0, bytes, offset[2], offset[0]);
			offset[2] += offset[0];
			offset[1] -= offset[0];
			offset[0] = 0;
			source = new byte[CAPACITY];
			int z = fileInputStream.read();
			err = fileInputStream.read(source);
			final byte tmp[] = decode();
			if (tmp == null)
				return -getDecodeError();
			System.arraycopy(tmp, 0, source, 0, z);
			offset[0] = z;
		}
	}

	public int read(final byte[] b, final int off, final int len) throws IOException
	{
		final byte[] bytes = new byte[len];
		final int x = read(bytes);
		System.arraycopy(bytes, 0, b, off, len);
		return x;
	}

	public long skip(final long n) throws IOException
	{
		if (n < 0)
			throw new IOException();
		final byte[] bytes = new byte[(int)n];
		return read(bytes);
	}

	private byte[] decode()
	{
		reverse(source, CAPACITY);

		final byte target[] = new byte[PAYLOAD];

		for (int i = 0; i < PAYLOAD; i++)
			target[i] = source[CAPACITY - 1 - i];

		byte syn[] = new byte[CAPACITY + 1];
		syndrome(source, syn);
		if (syn[0] == 0)
			return target;

		int r[] = errnum(syn);
		decodeError = r[0];
		int deter = r[1];
		if (decodeError == 4)
			return null;

		int e0, e1, e2, n0, n1, n2, w0, w1, w2, x0;
		byte x[] = new byte[3], z[] = new byte[4];
		int sols;

		switch (decodeError)
		{
			case 1:
				x0 = mul(syn[2], inv(syn[1]));
				w0 = mul(exp(syn[1], 2), inv(syn[2]));
				if (V_TO_E[x0] > 5)
					target[CAPACITY - 1 - V_TO_E[x0]] = (byte)add(target[CAPACITY - 1 - V_TO_E[x0]], w0);
				return target;

			case 2:
				z[0] = (byte)mul(add(mul(syn[1], syn[3]), exp(syn[2], 2)), inv(deter));
				z[1] = (byte)mul(add(mul(syn[2], syn[3]), mul(syn[1], syn[4])), inv(deter));
				z[2] = 1;
				z[3] = 0;

				sols = polysolve(z, x);
				if (sols != 2)
				{
					decodeError = 4;
					return null;
				}

				w0 = mul(z[0], syn[1]);
				w1 = add(mul(z[0], syn[2]), mul(z[1], syn[1]));
				n0 = CAPACITY - 1 - V_TO_E[inv(x[0])];
				n1 = CAPACITY - 1 - V_TO_E[inv(x[1])];
				e0 = mul(add(w0, mul(w1, x[0])), inv(z[1]));
				e1 = mul(add(w0, mul(w1, x[1])), inv(z[1]));

				if (n0 < PAYLOAD)
					target[n0] = (byte)add(target[n0], e0);
				if (n1 < PAYLOAD)
					target[n1] = (byte)add(target[n1], e1);

				return target;

			case 3:
				z[3] = 1;
				z[2] = (byte)mul(syn[1], mul(syn[4], syn[6]));
				z[2] = (byte)add(z[2], mul(syn[1], mul(syn[5], syn[5])));
				z[2] = (byte)add(z[2], mul(syn[5], mul(syn[3], syn[3])));
				z[2] = (byte)add(z[2], mul(syn[3], mul(syn[4], syn[4])));
				z[2] = (byte)add(z[2], mul(syn[2], mul(syn[5], syn[4])));
				z[2] = (byte)add(z[2], mul(syn[2], mul(syn[3], syn[6])));
				z[2] = (byte)mul(z[2], inv(deter));

				z[1] = (byte)mul(syn[1], mul(syn[3], syn[6]));
				z[1] = (byte)add(z[1], mul(syn[1], mul(syn[5], syn[4])));
				z[1] = (byte)add(z[1], mul(syn[4], mul(syn[3], syn[3])));
				z[1] = (byte)add(z[1], mul(syn[2], mul(syn[4], syn[4])));
				z[1] = (byte)add(z[1], mul(syn[2], mul(syn[3], syn[5])));
				z[1] = (byte)add(z[1], mul(syn[2], mul(syn[2], syn[6])));
				z[1] = (byte)mul(z[1], inv(deter));

				z[0] = (byte)mul(syn[2], mul(syn[3], syn[4]));
				z[0] = (byte)add(z[0], mul(syn[3], mul(syn[2], syn[4])));
				z[0] = (byte)add(z[0], mul(syn[3], mul(syn[5], syn[1])));
				z[0] = (byte)add(z[0], mul(syn[4], mul(syn[4], syn[1])));
				z[0] = (byte)add(z[0], mul(syn[3], mul(syn[3], syn[3])));
				z[0] = (byte)add(z[0], mul(syn[2], mul(syn[2], syn[5])));
				z[0] = (byte)mul(z[0], inv(deter));

				sols = polysolve (z, x);
				if (sols != 3)
				{
					decodeError = 4;
					return null;
				}

				w0 = mul(z[0], syn[1]);
				w1 = add(mul(z[0], syn[2]), mul(z[1], syn[1]));
				w2 = add(mul(z[0], syn[3]), add(mul(z[1], syn[2]), mul(z[2], syn[1])));

				n0 = CAPACITY - 1 - V_TO_E[inv(x[0])];
				n1 = CAPACITY - 1 - V_TO_E[inv(x[1])];
				n2 = CAPACITY - 1 - V_TO_E[inv(x[2])];

				e0 = add(w0, add(mul(w1, x[0]), mul(w2, exp(x[0], 2))));
				e0 = mul(e0, inv(add(z[1], exp(x[0], 2))));
				e1 = add(w0, add(mul(w1, x[1]), mul(w2, exp(x[1], 2))));
				e1 = mul(e1, inv(add(z[1], exp(x[1], 2))));
				e2 = add(w0, add(mul(w1, x[2]), mul(w2, exp(x[2], 2))));
				e2 = mul(e2, inv(add(z[1], exp(x[2], 2))));

				if (n0 < PAYLOAD)
					target[n0] = (byte)add(target[n0], e0);
				if (n1 < PAYLOAD)
					target[n1] = (byte)add(target[n1], e1);
				if (n2 < PAYLOAD)
					target[n2] = (byte)add(target[n2], e2);

				return target;

		}
		return null;
	}

	public int getDecodeError()
	{
		return decodeError;
	}

	private int evalpoly(final byte p[], final int x)
	{
		int y = 0;
		for (int i = 0; i < CAPACITY; i++)
			y = add(y, mul(p[i], exp(x, i)));
		return y;
	}

	private void syndrome(final byte c[], final byte s[])
	{
		s[0] = 0;
		for (byte i = 1; i < 7; i++)
		{
			s[i] = (byte)evalpoly(c, E_TO_V[i]);
			s[0] |= s[i];
		}
	}

	private int[] errnum(final byte s[])
	{
		int det = mul(s[2], mul(s[4], s[6]));
		det = add(det, mul(s[2], mul(s[5], s[5])));
		det = add(det, mul(s[6], mul(s[3], s[3])));
		det = add(det, mul(s[4], mul(s[4], s[4])));

		if (det != 0)
			return new int[] { 3, det };

		det = add(mul(s[2], s[4]), exp(s[3], (byte)2));
		if (det != 0)
			return new int[] { 2, det };

		det = s[1];
		if (det != 0)
			return new int[] { 1, det };

		return new int[] { 4, det };
	}

	private int polysolve(final byte polynom[], final byte roots[])
	{
		int numsol = 0;
		for (int i = 0; i < CAPACITY; i++)
		{
			int y = 0;
			for (int j = 0; j < 4; j++)
				y = add(y, mul(polynom[j], exp(E_TO_V[i], j)));
			if (y == 0)
				roots[numsol++] = (byte)E_TO_V[i];
		}
		return numsol;
	}
}
