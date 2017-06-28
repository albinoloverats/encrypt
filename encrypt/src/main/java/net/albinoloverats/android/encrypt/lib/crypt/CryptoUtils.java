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

import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.MacFactory;
import gnu.crypto.mac.IMac;
import gnu.crypto.mode.ModeFactory;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

public abstract class CryptoUtils
{
	private static final String NAME_TRIPLE_DES = "TRIPLEDES";
	private static final String NAME_3DES = "3DES";

	private static final String NAME_AES = "AES";
	private static final String NAME_RIJNDAEL128 = "RIJNDAEL128";

	private static final String NAME_CAST5 = "CAST5";
	private static final int KEY_SIZE_CAST5 = 128;

	private static final String NAME_WHIRLPOOL = "WHIRLPOOL";
	private static final String NAME_WHIRLPOOL_T = "WHIRLPOOL-T";

	private static final int KEY_SIZE_MINIMUM = 128;

	private static final String OMAC_NULL = "OMAC-NULL";

	private static final String OMAC_RIJNDAEL = "OMAC-RIJNDAEL";
	private static final String CMAC_AES = "CMAC_AES";

	private static final String OMAC_TRIPLE_DES = "OMAC-TRIPLEDES";
	private static final String CMAC_3DES = "CMAC_3DES";

	public static Set<String> getHashAlgorithmNames()
	{
		final Set<?> s = HashFactory.getNames();
		final Set<String> h = new TreeSet<>();
		for (final Object o : s)
		{
			String n = ((String)o).replace("-", "").toUpperCase(Locale.ENGLISH);
			if (n.equals(NAME_WHIRLPOOL))
				n = NAME_WHIRLPOOL_T;
			h.add(n);
		}
		return h;
	}

	public static IMessageDigest getHashAlgorithm(String name) throws NoSuchAlgorithmException
	{
		if (name.equals(NAME_WHIRLPOOL_T))
			name = NAME_WHIRLPOOL;
		final Set<?> s = HashFactory.getNames();
		for (final Object o : s)
			if (name.equals(((String)o).replace("-", "").toUpperCase(Locale.ENGLISH)))
				return HashFactory.getInstance((String)o);
		throw new NoSuchAlgorithmException(name);
	}

	public static Set<String> getCipherAlgorithmNames()
	{
		final Set<?> s = CipherFactory.getNames();
		final Set<String> h = new TreeSet<>();
		for (final Object o : s)
		{
			String n = ((String)o).replace("-", "").toUpperCase(Locale.ENGLISH);
			if (n.equals("NULL"))
				continue;
			final Set<Integer> keySizes = new TreeSet<>();
			for (final Iterator<?> iterator = CipherFactory.getInstance(n).keySizes(); iterator.hasNext();)
				keySizes.add((Integer)iterator.next());
			if (n.equals(NAME_TRIPLE_DES))
				n = NAME_3DES;
			if (keySizes.size() == 1 || n.equals(NAME_CAST5))
				h.add(n);
			else
				for (final Integer i : keySizes)
					if (NAME_RIJNDAEL128.equals(n + i * Byte.SIZE))
						h.add(NAME_AES);
					else if (i * Byte.SIZE >= KEY_SIZE_MINIMUM)
						h.add(n + i * Byte.SIZE);
		}
		return h;
	}

	public static IBlockCipher getCipherAlgorithm(String name) throws NoSuchAlgorithmException, InvalidKeyException
	{
		if (name.equals(NAME_3DES))
			name = NAME_TRIPLE_DES;
		else if (name.equals(NAME_AES))
			name = NAME_RIJNDAEL128;
		final Set<?> s = CipherFactory.getNames();
		for (final Object o : s)
		{
			final String n = ((String)o).replace("-", "").toUpperCase(Locale.ENGLISH);
			if (n.equals("NULL") || n.length() > name.length())
				continue;
			if (name.substring(0, n.length()).equals(n))
			{
				final Set<Integer> keySizes = new TreeSet<>();
				final IBlockCipher cipher = CipherFactory.getInstance(n);
				for (final Iterator<?> iterator = cipher.keySizes(); iterator.hasNext();)
					keySizes.add((Integer)iterator.next());
				if (keySizes.size() == 1 || n.equals(NAME_CAST5))
					return cipher;
				else
					for (final Integer i : keySizes)
						if (name.equals(n + i * Byte.SIZE))
							return cipher;
			}
		}
		throw new NoSuchAlgorithmException(name);
	}

	public static int getCipherAlgorithmKeySize(String name)
	{
		if (name.equals(NAME_3DES))
			name = NAME_TRIPLE_DES;
		if (name.equals(NAME_AES))
			name = NAME_RIJNDAEL128;
		final Set<?> s = CipherFactory.getNames();
		for (final Object o : s)
		{
			final String n = ((String)o).replace("-", "").toUpperCase(Locale.ENGLISH);
			if (n.equals("NULL") || n.length() > name.length())
				continue;
			if (name.substring(0, n.length()).equals(n))
			{
				final Set<Integer> keySizes = new TreeSet<>();
				final IBlockCipher cipher = CipherFactory.getInstance(n);
				for (final Iterator<?> iterator = cipher.keySizes(); iterator.hasNext();)
					keySizes.add((Integer)iterator.next());
				if (keySizes.size() == 1)
					return cipher.defaultKeySize() * Byte.SIZE;
				else if (name.endsWith(NAME_CAST5))
					return KEY_SIZE_CAST5;
				else
					for (final Integer i : keySizes)
						if (name.equals(n + i * Byte.SIZE))
							return i * Byte.SIZE;
			}
		}
		return 0;
	}

	public static Set<String> getCipherModeNames()
	{
		final Set<String> modes = new TreeSet<>();
		modes.add(ModeFactory.ECB_MODE.toUpperCase(Locale.ENGLISH));
		modes.add(ModeFactory.CBC_MODE.toUpperCase(Locale.ENGLISH));
		modes.add(ModeFactory.CFB_MODE.toUpperCase(Locale.ENGLISH));
		modes.add(ModeFactory.OFB_MODE.toUpperCase(Locale.ENGLISH));
		modes.add(ModeFactory.CTR_MODE.toUpperCase(Locale.ENGLISH));
		return modes;
	}

	public static Set<String> getMacAlgorithmNames()
	{
		final Set<?> s = MacFactory.getNames();
		final Set<String> m = new TreeSet<>();
		for (final Object o : s)
		{
			final String n = ((String)o).toUpperCase(Locale.ENGLISH).replace("SHA-", "SHA");
			if (n.equals(OMAC_NULL))
				continue;
			if (n.equals(OMAC_RIJNDAEL))
				m.add(CMAC_AES);
			else if (n.equals(OMAC_TRIPLE_DES))
				m.add(CMAC_3DES);
			else
				m.add(n.replace("HMAC-", "HMAC_").replace("OMAC-", "CMAC_"));
		}
		return m;
	}

	public static IMac getMacAlgorithm(String name) throws NoSuchAlgorithmException
	{
		final Set<?> s = MacFactory.getNames();
		for (final Object o : s)
		{
			final String n = ((String)o).toUpperCase(Locale.ENGLISH);
			String c = n.replace("SHA-", "SHA");
			c = c.replace("HMAC-", "HMAC_").replace("OMAC-", "CMAC_");
			if (n.equals(CMAC_AES))
				return MacFactory.getInstance(OMAC_RIJNDAEL);
			else if (n.equals(CMAC_3DES))
				return MacFactory.getInstance(OMAC_TRIPLE_DES);
			if (name.equals(c))
				return MacFactory.getInstance(n);
		}
		throw new NoSuchAlgorithmException(name);
	}
}
