package net.albinoloverats.android.encrypt;

public class Convert
{
    public static byte[] toBytes(final long l)
    {
        final byte b[] = new byte[8];
        b[0] = (byte)((l & 0xFF00000000000000L) >> 56);
        b[1] = (byte)((l & 0x00FF000000000000L) >> 48);
        b[2] = (byte)((l & 0x0000FF0000000000L) >> 40);
        b[3] = (byte)((l & 0x000000FF00000000L) >> 32);
        b[4] = (byte)((l & 0x00000000FF000000L) >> 24);
        b[5] = (byte)((l & 0x0000000000FF0000L) >> 16);
        b[6] = (byte)((l & 0x000000000000FF00L) >> 8);
        b[7] = (byte)( l & 0x00000000000000FFL);
        return b;
    }

    public static long longFromBytes(final byte[] b)
    {
        long l = ((long)b[0] & 0x00000000000000FFL) << 56;
        l |= ((long)b[1] & 0x00000000000000FFL) << 48;
        l |= ((long)b[2] & 0x00000000000000FFL) << 40;
        l |= ((long)b[3] & 0x00000000000000FFL) << 32;
        l |= ((long)b[4] & 0x00000000000000FFL) << 24;
        l |= ((long)b[5] & 0x00000000000000FFL) << 16;
        l |= ((long)b[6] & 0x00000000000000FFL) << 8;
        return l | ((long)b[7] & 0x00000000000000FFL);
    }

    public static byte[] toBytes(final int i)
    {
        final byte b[] = new byte[4];
        b[0] = (byte)((i & 0xFF000000) >> 24);
        b[1] = (byte)((i & 0x00FF0000) >> 16);
        b[2] = (byte)((i & 0x0000FF00) >> 8);
        b[3] = (byte)( i & 0x000000FF);
        return b;
    }

    public static int intFromBytes(final byte[] b)
    {
        int i = ((int)b[0] & 0x000000FF) << 24;
        i |= ((int)b[1] & 0x000000FF) << 16;
        i |= ((int)b[2] & 0x000000FF) << 8;
        return i | ((int)b[3] & 0x000000FF);
    }

    public static byte[] toBytes(final short s)
    {
        final byte b[] = new byte[2];
        b[0] = (byte)((s & 0xFF00) >> 8);
        b[1] = (byte)( s & 0x00FF);
        return b;
    }

    public static short shortFromBytes(final byte[] b)
    {
        short s = (short)(((int)b[0] & 0x00FF) << 8);
        return (short)(s | (short)((int)b[1] & 0x00FF));
    }

    public static byte[] toBytes(final byte x)
    {
        final byte b[] = new byte[1];
        b[0] = x;
        return b;
    }

    public static byte byteFromBytes(final byte[] b)
    {
        return (byte)((int)b[0] & 0x000000FF);
    }
}