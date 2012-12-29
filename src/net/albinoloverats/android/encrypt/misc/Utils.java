package net.albinoloverats.android.encrypt.misc;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public abstract class Utils
{
    public static String readFileAsString(final String filename)
    {
        FileInputStream f = null;
        try
        {
            final File file = new File(filename);
            f = new FileInputStream(file);
            final byte[] b = new byte[(int)file.length()];
            f.read(b);
            return new String(b);
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
