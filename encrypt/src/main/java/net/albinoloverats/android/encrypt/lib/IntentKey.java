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

package net.albinoloverats.android.encrypt.lib;

import java.util.Locale;

public enum IntentKey
{
	/* Intent keys for encrypting/decrypting */
	CLASS,
	ACTION,
	WAIT,
	ICON,
	SOURCE,
	OUTPUT,
	CIPHER,
	HASH,
	MODE,
	MAC,
	KDF_ITERATIONS,
	KEY_FILE,
	KEY,
	RAW,
	COMPRESS,
	FOLLOW,
	VERSION,
	/* Intent keys for progress updates */
	ENCRYPTING,
	CURRENT_FILE,
	CURRENT_OFFSET,
	CURRENT_SIZE,
	TOTAL_OFFSET,
	TOTAL_SIZE,
	STATUS;

	@Override
	public String toString()
	{
		return name().toLowerCase(Locale.ENGLISH);
	}
}
