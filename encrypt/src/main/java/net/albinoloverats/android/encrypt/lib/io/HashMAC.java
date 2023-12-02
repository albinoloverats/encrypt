package net.albinoloverats.android.encrypt.lib.io;

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.HMac;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class HashMAC
{
	public final IMessageDigest hash;
	public final HMac mac;
}
