/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2015, albinoloverats ~ Software Development
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

public enum Version
{
	_201108(0x72761df3e497c983L, "2011.08", 201108),
	_201110(0xbb116f7d00201110L, "2011.10", 201110),
	_201211(0x51d28245e1216c45L, "2012.11", 201211),
	_201302(0x5b7132ab5abb3c47L, "2013.02", 201302),
	_201311(0xf1f68e5f2a43aa5fL, "2013.11", 201311),
	_201406(0x8819d19069fae6b4L, "2014.06", 201406),
	_201501(0x63e7d49566e31bfbL, "2015.01", 201501),
	_201510(0x0dae4a923e4ae71dL, "2015.10", 201510),

	CURRENT(0x0dae4a923e4ae71dL, "CURRENT", 201510);

	final public long magicNumber;
	final public String display;
	final public int menu_id;

	Version(final long m, final String d, final int i)
	{
		magicNumber = m;
		display = d;
		menu_id = i;
	}

	public static Version parseMagicNumber(final long m, final Version d)
	{
		for (final Version v : Version.values())
			if (v.magicNumber == m)
				return v;
		return d;
	}
}
