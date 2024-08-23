package net.albinoloverats.android.encrypt.lib.io;

import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.HMac;
import lombok.AllArgsConstructor;

public record HashMAC(IMessageDigest hash, HMac mac)
{
}
