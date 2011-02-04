/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2011, albinoloverats ~ Software Development
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

#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#define GLADE_HOOKUP_OBJECT(component,widget,name) g_object_set_data_full (G_OBJECT (component), name, gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)
#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) g_object_set_data (G_OBJECT (component), name, widget)

#define TEXT_ABOUT \
    "encrypt is a small application which has been designed, from the\n"       \
    "beginning, to be as simple to use as can be and have the smallest file\n" \
    "size (download time) possible. The idea is small and simple, yet the\n"   \
    "encryption aims to be a strong as possible - as well as giving the\n"     \
    "user the choice about how their data is secured.\n"
#define TEXT_SITE    "https://albinoloverats.net/encrypt"
#define TEXT_CONTRIB "Ashley Anderson <amanderson@albinoloverats.net>"
#define TEXT_COPY    "Copyright (c) 2004-2009, albinoloverats ~ Software Development"

GtkWidget *create_window_main(void);
GtkWidget *create_window_about(void);
GtkWidget *create_window_wait(void);
GtkWidget *create_window_generate(void);

#endif /* _INTERFACE_H_ */
