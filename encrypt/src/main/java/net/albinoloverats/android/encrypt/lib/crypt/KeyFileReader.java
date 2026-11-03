package net.albinoloverats.android.encrypt.lib.crypt;

import lombok.val;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

final class KeyFileReader
{
	private static final int BUFFER_SIZE = 8192;

	private KeyFileReader()
	{
	}

	static byte[] read(final InputStream input) throws IOException
	{
		val output = new ByteArrayOutputStream();
		val buffer = new byte[BUFFER_SIZE];
		int count;
		while ((count = input.read(buffer)) != -1)
		{
			if (count == 0)
			{
				val next = input.read();
				if (next == -1)
					break;
				if (output.size() == Integer.MAX_VALUE)
					throw new IOException("Key file is too large");
				output.write(next);
				continue;
			}
			if (count > Integer.MAX_VALUE - output.size())
				throw new IOException("Key file is too large");
			output.write(buffer, 0, count);
		}
		if (output.size() == 0)
			throw new IOException("Key file is empty");
		return output.toByteArray();
	}
}
