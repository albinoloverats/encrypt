/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2024, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.lib;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum ProgressUpdate
{
	DONE(0),
	TOTAL(1),
	CURRENT(2);

	public final int value;

	public static ProgressUpdate fromValue(final int value)
	{
		for (final ProgressUpdate progressUpdate : ProgressUpdate.values())
			if (progressUpdate.value == value)
				return progressUpdate;
		return null;
	}
}
