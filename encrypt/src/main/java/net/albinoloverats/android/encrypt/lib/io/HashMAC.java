package net.albinoloverats.android.encrypt.lib.io;

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.HMac;

public class HashMAC
{
	public final IMessageDigest hash;
	public final HMac mac;

	public HashMAC(final IMessageDigest h, final HMac m)
	{
		hash = h;
		mac = m;
	}
}
