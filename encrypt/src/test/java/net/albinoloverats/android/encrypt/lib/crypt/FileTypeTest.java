package net.albinoloverats.android.encrypt.lib.crypt;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class FileTypeTest
{
	@Test
	public void resolvesEveryFileTypeId() throws CryptoProcessException
	{
		for (final FileType type : FileType.values())
			assertEquals(type, FileType.fromID(type.value));
	}

	@Test
	public void rejectsUnknownFileTypeIds()
	{
		try
		{
			FileType.fromID(-1);
			fail("Expected unknown file type to be rejected");
		}
		catch (final CryptoProcessException e)
		{
			assertEquals(Status.FAILED_UNKNOWN_TAG, e.code);
		}
	}
}
