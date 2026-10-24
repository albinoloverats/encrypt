package net.albinoloverats.android.encrypt.lib.crypt;

import lombok.val;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class StatusTest
{
	@Test
	public void parsesEveryStatusName()
	{
		for (val status : Status.values())
			assertEquals(status, Status.parseStatus(status.name()));
	}

	@Test
	public void returnsNullForUnknownStatusNames()
	{
		assertNull(Status.parseStatus("NOT_A_STATUS"));
	}

	@Test
	public void formatsStatusMessagesForDisplay()
	{
		assertEquals("Success", Status.SUCCESS.toString());
		assertEquals("Failed: invalid initialisation parameters!", Status.FAILED_INIT.toString());
	}
}
