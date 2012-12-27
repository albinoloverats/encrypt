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

package net.albinoloverats.android.encrypt.crypt;

public enum Status
{
    SUCCESS("Success"),
    INIT("Initialisation"),
    RUNNING("Running"),
    CANCELLED("Cancelled"),
    FAILED_INIT("Failed: Invalid initialisation parameters!"),
    FAILED_UNKNOWN_VERSION("Failed: Unsupported Version!"),
    FAILED_UNKNOWN_ALGORITH("Failed: Unsupported Algorithm!"),
    FAILED_DECRYPTION("Failed: Decryption Failure!"),
    FAILED_UNKNOWN_TAG("Failed: Unknown Tag!"),
    FAILED_CHECKSUM("Failed: Bad Checksum! (Possible data corruption.)"),
    FAILED_IO("Failed: Read/Write Error!"),
    FAILED_OUTPUT_MISMATCH("Failed: Target file type mismatch!"),
    FAILED_OTHER("Failed: Unknown Problem!");

    final public String message;

    private Status(final String message)
    {
        this.message = message;
    }
}
