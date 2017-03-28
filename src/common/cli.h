/*
 * Common code for providing a cmomand line progress bar
 * Copyright © 2005-2017, albinoloverats ~ Software Development
 * email: webmaster@albinoloverats.net
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

#ifndef _COMMON_CLI_H_
#define _COMMON_CLI_H_

#include <stdint.h>
#include <stdbool.h>

#define BPS 128

typedef enum
{
	CLI_DONE,
	CLI_INIT,
	CLI_RUN
}
cli_status_e;

/*!
 * \brief  Current progress
 *
 * Provide the foreground thread a way to check on the progress. Thus a
 * percentage can be calculated using 100 * offset / size. Either the
 * number of bytes, or directory entries depending on what you’re taking
 * the progress of.
 */
typedef struct
{
	uint64_t offset; /*!< Progress */
	uint64_t size;   /*!< Maximum */
}
cli_progress_t;

typedef struct
{
	cli_status_e *status;
	cli_progress_t *current;
	cli_progress_t *total;
}
cli_t;

typedef struct
{
	uint64_t time;
	uint64_t bytes;
}
cli_bps_t;

extern void cli_display(cli_t *) __attribute__((nonnull(1)));
extern double cli_calc_bps(cli_bps_t *) __attribute__((nonnull(1)));

#endif /* _COMMON_CLI_H_ */
