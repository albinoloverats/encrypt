package net.albinoloverats.android.encrypt.lib;

public enum IntentKey
{
	/* Intent keys for encrypting/decrypting */
	CLASS,
	ACTION,
	WAIT,
	ICON,
	SOURCE,
	OUTPUT,
	CIPHER,
	HASH,
	MODE,
	MAC,
	KDF_ITERATIONS,
	KEY_FILE,
	KEY,
	RAW,
	COMPRESS,
	FOLLOW,
	VERSION,
	/* Intent keys for progress updates */
	ENCRYPTING,
	CURRENT_FILE,
	CURRENT_OFFSET,
	CURRENT_SIZE,
	TOTAL_OFFSET,
	TOTAL_SIZE,
	STATUS
}
