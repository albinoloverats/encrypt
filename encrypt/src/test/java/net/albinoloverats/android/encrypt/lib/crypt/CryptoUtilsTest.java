package net.albinoloverats.android.encrypt.lib.crypt;

import gnu.crypto.cipher.IBlockCipher;
import gnu.crypto.hash.IMessageDigest;
import gnu.crypto.mac.HMac;
import lombok.val;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CryptoUtilsTest
{
	@Test
	public void providesHashNamesThatResolveToHashAlgorithms() throws NoSuchAlgorithmException
	{
		assertFalse(CryptoUtils.getHashAlgorithmNames().isEmpty());
		for (val name : CryptoUtils.getHashAlgorithmNames())
			assertNotNull(CryptoUtils.getHashAlgorithm(name));
		assertNotNull(CryptoUtils.getHashAlgorithm("WHIRLPOOL-T"));
	}

	@Test
	public void providesCipherNamesThatResolveToCipherAlgorithms() throws NoSuchAlgorithmException
	{
		assertFalse(CryptoUtils.getCipherAlgorithmNames().isEmpty());
		for (val name : CryptoUtils.getCipherAlgorithmNames())
		{
			val cipher = CryptoUtils.getCipherAlgorithm(name);
			assertNotNull(cipher);
			assertTrue(CryptoUtils.getCipherAlgorithmKeySize(name) > 0);
		}
	}

	@Test
	public void providesMacNamesThatResolveToMacAlgorithms() throws NoSuchAlgorithmException
	{
		assertFalse(CryptoUtils.getMacAlgorithmNames().isEmpty());
		for (val name : CryptoUtils.getMacAlgorithmNames())
			assertNotNull(CryptoUtils.getMacAlgorithm(name));
		assertEquals("HMAC_SHA256", CryptoUtils.hmacFromHash("sha256"));
		assertEquals("SHA256", CryptoUtils.hashFromHmac("hmac_sha256"));
		assertNotNull(CryptoUtils.getMacAlgorithm("HMAC_WHIRLPOOL-T"));
	}

	@Test
	public void rejectsUnknownAlgorithms()
	{
		try
		{
			CryptoUtils.getHashAlgorithm("NOT_A_HASH");
			fail("Expected unknown hash to be rejected");
		}
		catch (final NoSuchAlgorithmException expected)
		{
			assertEquals("NOT_A_HASH", expected.getMessage());
		}

		try
		{
			CryptoUtils.getCipherAlgorithm("NOT_A_CIPHER");
			fail("Expected unknown cipher to be rejected");
		}
		catch (final NoSuchAlgorithmException expected)
		{
			assertEquals("NOT_A_CIPHER", expected.getMessage());
		}
	}
}
