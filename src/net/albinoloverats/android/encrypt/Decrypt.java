package net.albinoloverats.android.encrypt;

import java.io.File;

public class Decrypt extends Encrypt
{
    public Decrypt(final File sourceFile, final File outputFile, final byte[] keyData)
    {
        super(sourceFile, outputFile, keyData, false);
    }
}
