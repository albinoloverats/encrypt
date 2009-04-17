/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright (c) 2005-2009, albinoloverats ~ Software Development
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

#ifndef _CALLBACKS_H_
  #define _CALLBACKS_H_

  #include <gtk/gtk.h>

  #define PLUGIN_DETAILS_MASK \
    "\n%s\n" \
      " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" \
    "\n%s\n" \
      " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" \
    "\n%s\n" \
      " %s : %s\n" " %s : %s\n" " %s : %s\n" " %s : %s\n" \
    "\n%s\n" \
      "%s"

typedef struct args_t
{
    int64_t (*fp)(int64_t, int64_t, uint8_t *);
    int64_t file_in;
    int64_t file_out;
    uint8_t *key_data;
}
args_t;

void *thread_main(void *);

void on_button_about_clicked(GtkWidget *);
void on_button_do_clicked(GtkWidget *);
void on_button_about_close_clicked(GtkWidget *);
void on_button_wait_close_clicked(GtkWidget *);
void on_button_generate_clicked(void);
void on_button_gen_go_clicked(GtkWidget *);
void on_button_gen_close_clicked(GtkWidget *);
void on_entry_gen_save_name_changed(GtkWidget *);

#endif /* _CALLBACKS_H_ */
