package net.albinoloverats.android.encrypt.lib.crypt;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class TagTest
{
	@Test
	public void resolvesEveryTagValue() throws CryptoProcessException
	{
		for (final Tag tag : Tag.values())
			assertEquals(tag, Tag.fromValue(tag.value));
	}

	@Test
	public void rejectsUnknownTagValues()
	{
		try
		{
			Tag.fromValue(-1);
			fail("Expected unknown tag to be rejected");
		}
		catch (final CryptoProcessException e)
		{
			assertEquals(Status.FAILED_UNKNOWN_TAG, e.code);
		}
	}
}
