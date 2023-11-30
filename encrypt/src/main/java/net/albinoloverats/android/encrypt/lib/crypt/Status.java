/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2024, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.lib.crypt;

public enum Status
{
	/* success and running states */
	SUCCESS("Success"),
	INIT("Initialisation"),
	RUNNING("Running"),
	CANCELLED("Cancelled"),
	/* failure with compatibility mode and directories */
	FAILURE_COMPATIBILITY("Failed: Compatibility mode cannot encrypt directories!"),
	/* failures - decryption did not complete */
	FAILED_INIT("Failed: Invalid initialisation parameters!"),
	FAILED_UNKNOWN_VERSION("Failed: Unsupported version!"),
	FAILED_UNKNOWN_ALGORITHM("Failed: Unsupported algorithm!"),
	FAILED_DECRYPTION("Failed: Decryption failure!\n(Invalid password)"),
	FAILED_UNKNOWN_TAG("Failed: Unsupported feature!"),
	FAILED_IO("Failed: Read/Write error!"),
	FAILED_KEY("Failed: Key generation error!"),
	FAILED_OUTPUT_MISMATCH("Failed: Invalid target file type!"),
	FAILED_COMPRESSION_ERROR("Failed: Compression Error!"),
	FAILED_OTHER("Failed An unknown error has occurred!"),
	/* warnings - decryption finished but with possible errors */
	WARNING_CHECKSUM("Warning: Bad checksum!\n(Possible data corruption)"),
	WARNING_LINK("Warning: Could not extract all files!\n(Symlinks are unsupported");

	final public String message;

	Status(final String message)
	{
		this.message = message;
	}

	public static Status parseStatus(final String s)
	{
		for (final Status status : Status.values())
			if (status.name().equals(s))
				return status;
		return null;
	}

	@Override
	public String toString()
	{
		return message.charAt(0) + message.substring(1).replace('_', ' ').toLowerCase();
	}
}
