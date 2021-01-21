/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2021, albinoloverats ~ Software Development
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

public enum Tag
{
	SIZE(0),
	BLOCKED(1),
	COMPRESSED(2),
	DIRECTORY(3),
	FILENAME(4);

	final public int value;

	Tag(final int value)
	{
		this.value = value;
	}

	public static Tag fromValue(final int value) throws CryptoProcessException
	{
		for (final Tag tag : Tag.values())
			if (tag.value == value)
				return tag;
		throw new CryptoProcessException(Status.FAILED_UNKNOWN_TAG);
	}
}
