/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2014, albinoloverats ~ Software Development
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

import net.albinoloverats.android.encrypt.Main;
import net.albinoloverats.android.encrypt.R;

public enum Status
{
    /* success and running states */
    SUCCESS(R.string.success),
    INIT(R.string.init),
    RUNNING(R.string.running),
    CANCELLED(R.string.cancelled),
    /* failure with compatibility mode and directories */
    FAILURE_COMPATIBILITY(R.string.failed_compatibility),
    /* failures - decryption did not complete */
    FAILED_INIT(R.string.failed_init),
    FAILED_UNKNOWN_VERSION(R.string.failed_unknown_version),
    FAILED_UNKNOWN_ALGORITHM(R.string.failed_unknown_algorithm),
    FAILED_DECRYPTION(R.string.failed_decryption),
    FAILED_UNKNOWN_TAG(R.string.failed_unknown_tag),
    FAILED_IO(R.string.failed_io),
    FAILED_KEY(R.string.failed_key),
    FAILED_OUTPUT_MISMATCH(R.string.failed_output_mismatch),
    FAILED_OTHER(R.string.failed_other),
    /* warnings - decryption finished but with possible errors */
    WARNING_CHECKSUM(R.string.warning_checksum),
    WARNING_LINK(R.string.warning_link);

    final public String message;

    private Status(final int message)
    {
        this.message = Main.getContext().getString(message);
    }

    public static Status parseStatus(final String s)
    {
        for (final Status status : Status.values())
            if (status.name().equals(s))
                return status;
        return null;
    }
}
