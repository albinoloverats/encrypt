package net.albinoloverats.android.encrypt.lib.io;

import java.io.IOException;

final class OutputStreamState
{
	private boolean open = true;

	void ensureOpen() throws IOException
	{
		if (!open)
			throw new IOException("Stream is closed");
	}

	boolean close()
	{
		if (!open)
			return false;
		open = false;
		return true;
	}
}
