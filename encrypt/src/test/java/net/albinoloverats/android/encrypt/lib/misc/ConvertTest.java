package net.albinoloverats.android.encrypt.lib.misc;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ConvertTest
{
	@Test
	public void convertsHexStringsToBytes()
	{
		assertArrayEquals(new byte[] { 0, 15, (byte)0xA0, (byte)0xFF }, Convert.toBytes("000FA0ff"));
		assertArrayEquals(new byte[0], Convert.toBytes(""));
	}

	@Test
	public void convertsLongsToAndFromBigEndianBytes()
	{
		for (final long value : new long[] { 0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE })
			assertEquals(value, Convert.longFromBytes(Convert.toBytes(value)));
	}

	@Test
	public void convertsIntsToAndFromBigEndianBytes()
	{
		for (final int value : new int[] { 0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE })
			assertEquals(value, Convert.intFromBytes(Convert.toBytes(value)));
	}

	@Test
	public void convertsShortsToAndFromBigEndianBytes()
	{
		for (final short value : new short[] { 0, 1, -1, Short.MIN_VALUE, Short.MAX_VALUE })
			assertEquals(value, Convert.shortFromBytes(Convert.toBytes(value)));
	}

	@Test
	public void convertsBytesAndBooleans()
	{
		assertArrayEquals(new byte[] { (byte)0xFF }, Convert.toBytes((byte)0xFF));
		assertEquals((byte)0xFF, Convert.byteFromBytes(new byte[] { (byte)0xFF }));
		assertArrayEquals(new byte[] { 1 }, Convert.toBytes(true));
		assertArrayEquals(new byte[] { 0 }, Convert.toBytes(false));
		assertTrue(Convert.booleanFromBytes(new byte[] { 1 }));
		assertTrue(Convert.booleanFromBytes(new byte[] { (byte)0xFF }));
		assertFalse(Convert.booleanFromBytes(new byte[] { 0 }));
	}
}
