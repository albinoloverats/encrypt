/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt;

import gnu.crypto.cipher.CipherFactory;
import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.HashFactory;
import gnu.crypto.hash.IMessageDigest;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

public abstract class AlgorithmNames
{
	private static final String NAME_TRIPLE_DES = "TRIPLEDES";
	private static final String NAME_3DES = "3DES";

	private static final String NAME_AES = "AES";
	private static final String NAME_RIJNDAEL128 = "RIJNDAEL128";

	private static final String NAME_CAST5 = "CAST5";
	private static final int KEY_SIZE_CAST5 = 128;

	private static final int KEY_SIZE_MINIMUM = 128;

    public static Set<String> getHashAlgorithmNames()
    {
        final Set<?> s = HashFactory.getNames();
        final Set<String> h = new TreeSet<String>();
        for (final Object o : s)
            h.add(((String)o).replace("-", "").toUpperCase());
        return h;
    }

    public static IMessageDigest getHashAlgorithm(final String name) throws NoSuchAlgorithmException
    {
        final Set<?> s = HashFactory.getNames();
        for (final Object o : s)
                if (name.equals(((String)o).replace("-", "").toUpperCase()))
                        return HashFactory.getInstance((String)o);
        throw new NoSuchAlgorithmException(name);
    }

    public static Set<String> getCipherAlgorithmNames()
    {
        final Set<?> s = CipherFactory.getNames();
        final Set<String> h = new TreeSet<String>();
        for (final Object o : s)
        {
            String n = ((String)o).replace("-", "").toUpperCase();
            if (n.equals("NULL"))
                continue;
            final Set<Integer> keySizes = new TreeSet<Integer>();
            for (final Iterator<?> iterator = CipherFactory.getInstance(n).keySizes(); iterator.hasNext();)
                keySizes.add((Integer)iterator.next());
            if (n.equals(NAME_TRIPLE_DES))
            	n = NAME_3DES;
            if (keySizes.size() == 1 || n.equals(NAME_CAST5))
                h.add(n);
            else
                for (final Integer i : keySizes)
                    if (i.intValue() * Byte.SIZE < KEY_SIZE_MINIMUM)
                        continue;
                    else if (NAME_RIJNDAEL128.equals(n + i.intValue() * Byte.SIZE))
                        h.add(NAME_AES);
                    else
                        h.add(n + i.intValue() * Byte.SIZE);
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
            String n = ((String)o).replace("-", "").toUpperCase();
            if (n.equals("NULL"))
                continue;
            if (n.length() > name.length())
            	continue;
            if (name.substring(0, n.length()).equals(n))
            {
                final Set<Integer> keySizes = new TreeSet<Integer>();
                final IBlockCipher cipher = CipherFactory.getInstance(n);
				for (final Iterator<?> iterator = cipher.keySizes(); iterator.hasNext();)
                    keySizes.add((Integer)iterator.next());
                if (keySizes.size() == 1 || n.equals(NAME_CAST5))
                    return cipher;
                else
                    for (final Integer i : keySizes)
                        if (name.equals(n + i.intValue() * Byte.SIZE))
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
            String n = ((String)o).replace("-", "").toUpperCase();
            if (n.equals("NULL"))
                continue;
            if (n.length() > name.length())
            	continue;
            if (name.substring(0, n.length()).equals(n))
            {
                final Set<Integer> keySizes = new TreeSet<Integer>();
                final IBlockCipher cipher = CipherFactory.getInstance(n);
				for (final Iterator<?> iterator = cipher.keySizes(); iterator.hasNext();)
                    keySizes.add((Integer)iterator.next());
                if (keySizes.size() == 1)
                    return cipher.defaultKeySize() * Byte.SIZE;
                else if (name.endsWith(NAME_CAST5))
                    return KEY_SIZE_CAST5;
                else
                    for (final Integer i : keySizes)
                        if (i.intValue() * Byte.SIZE < KEY_SIZE_MINIMUM)
                            continue;
                        else if (name.equals(n + i.intValue() * Byte.SIZE))
                            return i.intValue() * Byte.SIZE;
            }
        }
        return 0;
    }
}