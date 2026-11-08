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

package net.albinoloverats.android.encrypt.lib.io;

import lombok.val;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class OutputStreamContractTest
{
	@Test
	public void eccOutputValidatesSlicesAndRejectsWritesAfterClose() throws IOException
	{
		val sink = new CloseCountingOutputStream();
		val output = new ECCFileOutputStream(sink);
		val data = new byte[] { 1, 2, 3 };
		output.write(data, 1, 2);
		assertThrows(IndexOutOfBoundsException.class, () -> output.write(data, -1, 1));
		assertThrows(IndexOutOfBoundsException.class, () -> output.write(data, 2, 2));
		output.close();
		output.close();
		assertEquals(1, sink.closeCount);
		assertThrows(IOException.class, () -> output.write(1));
	}

	@Test
	public void encryptedOutputValidatesSlicesAndRejectsWritesAfterClose() throws IOException
	{
		val sink = new CloseCountingOutputStream();
		val output = new EncryptedFileOutputStream(sink);
		val data = new byte[] { 1, 2, 3 };
		output.write(data, 1, 2);
		assertThrows(IndexOutOfBoundsException.class, () -> output.write(data, -1, 1));
		assertThrows(IndexOutOfBoundsException.class, () -> output.write(data, 2, 2));
		output.close();
		output.close();
		assertEquals(1, sink.closeCount);
		assertThrows(IOException.class, () -> output.write(1));
	}

	@Test
	public void bothOutputsPropagateUnderlyingWriteFailures()
	{
		val failure = new IOException("sink failed");
		val eccOutput = new ECCFileOutputStream(new FailingOutputStream(failure));
		assertEquals(failure, assertThrows(IOException.class, () -> eccOutput.write(new byte[] { 1 })));

		val encryptedOutput = new EncryptedFileOutputStream(new FailingOutputStream(failure));
		assertEquals(failure, assertThrows(IOException.class, () -> encryptedOutput.write(new byte[] { 1 })));
	}

	private static class CloseCountingOutputStream extends ByteArrayOutputStream
	{
		private int closeCount;

		@Override
		public void close() throws IOException
		{
			closeCount++;
			super.close();
		}
	}

	private static class FailingOutputStream extends OutputStream
	{
		private final IOException failure;

		private FailingOutputStream(final IOException failure)
		{
			this.failure = failure;
		}

		@Override
		public void write(final int b) throws IOException
		{
			throw failure;
		}

		@Override
		public void write(final byte[] b, final int off, final int len) throws IOException
		{
			throw failure;
		}
	}
}
