/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2013, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.misc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public abstract class Utils
{
    public static byte[] readFileBytes(final String filename)
    {
        FileInputStream f = null;
        try
        {
            final File file = new File(filename);
            f = new FileInputStream(file);
            final byte[] b = new byte[(int)file.length()];
            f.read(b);
            return b;
        }
        catch (final Exception e)
        {
            return null;
        }
        finally
        {
            try
            {
                if (f != null)
                    f.close();
            }
            catch (final IOException e)
            {
                ;
            }
        }
    }
}
