/*
 * Common code which is used to call Objective-C methods on OS X
 * Copyright © 2005-2020, albinoloverats ~ Software Development
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

#ifdef __APPLE__

#import <Foundation/Foundation.h>
#ifdef __MAC_OS_X_VERSION_MAX_ALLOWED
	#import <Appkit/AppKit.h>
#endif

#import <time.h>

#import "osx.h"

void osx_open_file(char *path)
{
	[[NSWorkspace sharedWorkspace] openFile:[NSString stringWithUTF8String:path]];
	sleep(1);
	return;
}

#endif
