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
