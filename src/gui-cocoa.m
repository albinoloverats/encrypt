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

//#import <NSMenuItem.h>

#import <sys/stat.h>
#import <sys/time.h>
#import <string.h>
#import <math.h>

#import "gui.h"
#import "gui-cocoa.h"

#import "common.h"
#import "version.h"
#import "error.h"

#import "crypt.h"
#import "encrypt.h"
#import "decrypt.h"
#import "init.h"
#import "cli.h"

@implementation AppDelegate

#if 0
char *gui_file_hack_source = NULL;
char *gui_file_hack_output = NULL;
#endif

static bool encrypted = true;
static bool compress = true;
static bool follow = false;
static bool running = false;
static version_e version = VERSION_CURRENT;
static key_source_e key_source = KEY_SOURCE_PASSWORD;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    version_check_for_update(ENCRYPT_VERSION, UPDATE_URL);

    args_t args = init(0, NULL);

    [self auto_select_algorithms:args.cipher:args.hash:args.mode];

    bool z = true;
    for (NSMenuItem *m in [_sourceFileChooser itemArray])
    {
        const char *t = [[m title] UTF8String];
        if (!strcmp(t, SELECT_FILE) || !strcmp(t, SELECT_OTHER))
            continue;
        else if (z && !strlen(t))
        {
            z = false;
            continue;
        }
        [_sourceFileChooser removeItemWithTitle:[NSString stringWithUTF8String:t]];
    }

#if 0
    if (gui_file_hack_source)
    {
        [_sourceFileChooser addItemWithTitle:[NSString stringWithUTF8String:basename(gui_file_hack_source)]];
        [NSUserDefaults.standardUserDefaults setValue:[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] forKeyPath:[NSString stringWithUTF8String:gui_file_hack_source]];
    }
#endif

    z = true;
    for (NSMenuItem *m in [_outputFileChooser itemArray])
    {
        const char *t = [[m title] UTF8String];
        if (!strcmp(t, SELECT_FILE) || !strcmp(t, SELECT_NEW) || !strcmp(t, SELECT_OTHER))
            continue;
        else if (z && !strlen(t))
        {
            z = false;
            continue;
        }
        [_outputFileChooser removeItemWithTitle:[NSString stringWithUTF8String:t]];
    }

#if 0
    if (gui_file_hack_output)
    {
        [_outputFileChooser addItemWithTitle:[NSString stringWithUTF8String:gui_file_hack_output]];
        [NSUserDefaults.standardUserDefaults setValue:[NSUserDefaults.standardUserDefaults valueForKeyPath:@OUTPUT_FILE] forKeyPath:[NSString stringWithUTF8String:gui_file_hack_output]];
    }
#endif

    z = true;
    for (NSMenuItem *m in [_keyFileChooser itemArray])
    {
        const char *t = [[m title] UTF8String];
        if (!strcmp(t, SELECT_KEY) || !strcmp(t, SELECT_OTHER))
            continue;
        else if (z && !strlen(t))
        {
            z = false;
            continue;
        }
        [_keyFileChooser removeItemWithTitle:[NSString stringWithUTF8String:t]];
    }

    /* set menu options based of config settings */
    compress = args.compress;
    [_compress setState:args.compress];

    follow = args.follow;
    [_follow setState:args.follow];

    version = parse_version(args.version);
    for (version_e v = VERSION_CURRENT; v > VERSION_UNKNOWN; v--)
    {
        NSMenuItem *m = [[NSMenuItem alloc] initWithTitle:[NSString stringWithUTF8String:get_version_string(v)] action:@selector(versionToggle:) keyEquivalent:@""];
        [m setState:NSOffState];
        [m setEnabled:TRUE];
        [m setTarget:self];
        if (v == version)
            [m setState:NSOnState];
        [_version addItem:m];
    }

    key_source = args.key_source;
    [self keySourceToggle];

    [_statusBar setStringValue:@STATUS_BAR_READY];

    return;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication {
    return YES;
}

- (IBAction)compressionToggle:(id)pId
{
    compress = !(bool)[_compress state];
    [_compress setState:compress];
    update_config(CONF_COMPRESS, compress ? CONF_TRUE : CONF_FALSE);
}

- (IBAction)followToggle:(id)pId
{
    follow = !(bool)[_follow state];
    [_follow setState:follow];
    update_config(CONF_FOLLOW, follow ? CONF_TRUE : CONF_FALSE);
}

- (IBAction)versionToggle:(id)pId
{
    NSMenuItem *i = [_version highlightedItem];
    const char *v = [[i title] UTF8String];
    version = parse_version(v);
    for (NSMenuItem *m in [_version itemArray])
        [m setState:NSOffState];
    [i setState:NSOnState];
    update_config(CONF_VERSION, (char *)get_version_string(version));
}

- (IBAction)ioFileChoosen:(id)pId
{
    Boolean en = FALSE;
    const char *open_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] UTF8String];
    const char *save_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@OUTPUT_FILE] UTF8String];

    if (!open_link || !strlen(open_link))
        goto clean_up;

    char *open_file = NULL;
    if (open_link[0] == '~')
        asprintf(&open_file, "%s/%s", getenv("HOME"), open_link + 1);
    else
        open_file = strdup(open_link);
    /*
     * check if the file is encrypted or not
     */
    char *c = NULL;
    char *h = NULL;
    char *m = NULL;
    if ((encrypted = is_encrypted(open_file, &c, &h, &m)))
        [self auto_select_algorithms:c:h:m];
    [_encryptButton setTitle:encrypted ? @LABEL_DECRYPT : @LABEL_ENCRYPT];

    if (!save_link || !strlen(save_link))
        goto clean_up;

    char *save_file = NULL;
    if (save_link[0] == '~')
        asprintf(&save_file, "%s/%s", getenv("HOME"), save_link + 1);
    else
        save_file = strdup(save_link);
    /*
     * if the destination exists, it has to be a regular file
     */
    struct stat s;
    stat(save_file, &s);
    free(save_file);
    if (errno != ENOENT && !(S_ISREG(s.st_mode) || S_ISDIR(s.st_mode)))
        goto clean_up;

    en = TRUE;

clean_up:

    if (!encrypted)
    {
        [_cipherCombo setEnabled:en];
        [_hashCombo setEnabled:en];
        [_modeCombo setEnabled:en];
    }

    [self cipherHashSelected:pId];
}

- (IBAction)cipherHashSelected:(id)pId
{
    const char *cipher = [[[_cipherCombo selectedItem] title] UTF8String];
    const char *hash = [[[_hashCombo selectedItem] title] UTF8String];
    const char *mode = [[[_modeCombo selectedItem] title] UTF8String];

    if ((cipher && strcasecmp(cipher, SELECT_CIPHER)) &&
          (hash && strcasecmp(hash, SELECT_HASH)) &&
          (mode && strcasecmp(mode, SELECT_MODE)))
    {
        [self keySourceSelected:pId];
        [_keyFileChooser setEnabled:true];
        [_passwordField setEnabled:true];

        update_config(CONF_CIPHER, cipher);
        update_config(CONF_HASH, hash);
        update_config(CONF_MODE, mode);
    }
    else
    {
        // Unselected either cipher/hash/mode, disable all options below
        [_keyFileChooser setEnabled:false];
        [_passwordField setEnabled:false];
        [_encryptButton setEnabled:false];
    }
}

- (IBAction)keySourceSelected:(id)pId
{
    NSMenuItem *m = [_keySource highlightedItem];
    const char *s = [[m title] UTF8String];
    if (!s)
        return;
    if (!strcasecmp(s, KEY_SOURCE[KEY_SOURCE_PASSWORD]))
        key_source = KEY_SOURCE_PASSWORD;
    else
        key_source = KEY_SOURCE_FILE;
    update_config(CONF_KEY, KEY_SOURCE[key_source]);
    [self keySourceToggle];
}

- (void)keySourceToggle
{
    [_keySourceFile setState:key_source == KEY_SOURCE_FILE ? NSOnState : NSOffState];
    [_keySourcePassword setState:key_source == KEY_SOURCE_PASSWORD ? NSOnState : NSOffState];

    [_keyFileChooserButton setHidden:key_source != KEY_SOURCE_FILE];
    [_passwordField setHidden:key_source != KEY_SOURCE_PASSWORD];
}

- (IBAction)keyFileChoosen:(id)pId
{
    const char *key_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@KEYSRC_FILE] UTF8String];
    BOOL en = FALSE;

    if (!key_link || !strlen(key_link))
        goto clean_up;

    char *key_file = NULL;
    if (key_link[0] == '~')
        asprintf(&key_file, "%s/%s", getenv("HOME"), key_link + 1);
    else
        key_file = strdup(key_link);

    struct stat s;
    stat(key_file, &s);
    free(key_file);
    if (!S_ISREG(s.st_mode))
        goto clean_up;

    en = TRUE;

clean_up:

    [_encryptButton setEnabled:en];
}

- (IBAction)passwordFieldUpdated:(id)pId
{
    // Toggle encrypt/decrypt button based on passphrase length
    [_encryptButton setEnabled:([[_passwordField stringValue] length] > 0)];
}


- (IBAction)encryptButtonPushed:(id)pId
{
    [_popup setIsVisible:TRUE];
    [_progress_current setHidden:FALSE];
    [_percent_current setHidden:FALSE];
    [self performSelectorInBackground:@selector(display_gui:)withObject:nil];
}

- (void)display_gui:(id)pId
{
    /*
     * open files
     */
    const char *open_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] UTF8String];
    const char *save_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@OUTPUT_FILE] UTF8String];

    char *open_file = NULL;
    if (open_link[0] == '~')
        asprintf(&open_file, "%s/%s", getenv("HOME"), open_link + 1);
    else
        open_file = strdup(open_link);

    char *save_file = NULL;
    if (save_link[0] == '~')
        asprintf(&save_file, "%s/%s", getenv("HOME"), save_link + 1);
    else
        save_file = strdup(save_link);

    /*
     * get raw key data
     */
    uint8_t *key;
    size_t length;
    if (key_source == KEY_SOURCE_FILE)
    {
        const char *key_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@KEYSRC_FILE] UTF8String];

        char *key_file = NULL;
        if (key_link[0] == '~')
            asprintf(&key_file, "%s/%s", getenv("HOME"), key_link + 1);
        else
            key_file = strdup(key_link);
        key = (uint8_t *)strdup(key_file);
        free(key_file);
        length = 0;
    }
    else
    {
        key = (uint8_t *)strdup([[_passwordField stringValue] UTF8String]);
        length = strlen((char *)key);
    }

    crypto_t *c;
    if (!encrypted)
        c = encrypt_init(open_file, save_file,
                         (char *)[[[_cipherCombo selectedItem] title] UTF8String],
                         (char *)[[[_hashCombo selectedItem] title] UTF8String],
                         (char *)[[[_modeCombo selectedItem] title] UTF8String],
                         key, length, false, compress, follow, version);
    else
        c = decrypt_init(open_file, save_file, NULL, NULL, NULL, key, length, false);

    free(open_file);
    free(save_file);
    free(key);

    running = true;

    execute(c);

    bps_t bps[BPS];
    memset(bps, 0x00, BPS * sizeof( bps_t ));
    int b = 0;

    while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
    {
        if (!running)
            c->status = STATUS_CANCELLED;

        struct timespec s = { 0, MILLION };
        nanosleep(&s, NULL);

        if (c->status == STATUS_INIT)
            continue;

        float pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
        if (c->total.offset == c->total.size)
            pc = PERCENT * c->total.offset / c->total.size;

        [_progress_total setDoubleValue:pc];
        char *tpc = NULL;
        asprintf(&tpc, "%3.0f %%", pc);
        [_percent_total setStringValue:[NSString stringWithUTF8String:tpc]];
        free(tpc);

        if (c->total.size == 1)
        {
            [_progress_current setHidden:TRUE];
            [_percent_current setHidden:TRUE];
        }
        else
        {
            float cp = PERCENT * c->current.offset / c->current.size;
            [_progress_current setDoubleValue:cp];
            char *cpc = NULL;
            asprintf(&cpc, "%3.0f %%", cp);
            [_percent_current setStringValue:[NSString stringWithUTF8String:cpc]];
            free(cpc);
        }

        struct timeval tv;
        gettimeofday(&tv, NULL);
        bps[b].time = tv.tv_sec * MILLION + tv.tv_usec;
        bps[b].bytes = c->current.offset;
        float val = cli_calc_bps(bps);
        b++;
        if (b >= BPS)
            b = 0;

        char *bps_label = NULL;
        if (isnan(val) || val == 0.0f || val >= BILLION)
            asprintf(&bps_label, "---.- B/s");
        else
        {
            if (val < THOUSAND)
                asprintf(&bps_label, "%5.1f B/s", val);
            else if (val < MILLION)
                asprintf(&bps_label, "%5.1f KB/s", val / KILOBYTE);
            else if (val < THOUSAND_MILLION)
                asprintf(&bps_label, "%5.1f MB/s", val / MEGABYTE);
            else if (val < BILLION)
                asprintf(&bps_label, "%5.1f GB/s", val / GIGABYTE);
            // we were getting some erratic values because of this
//            else
//                asprintf(&bps_label, "%5.1f TB/s", val / TERABYTE);
        }
        if (bps_label)
            [_progress_label setStringValue:[NSString stringWithUTF8String:bps_label]];
    }

    [_progress_label setStringValue:[NSString stringWithUTF8String:status(c)]];
    [_statusBar setStringValue:[NSString stringWithUTF8String:status(c)]];
    [_closeButton setHidden:FALSE];
    [_cancelButton setHidden:TRUE];

    deinit(&c);

    return;
}

- (IBAction)cancelButtonPushed:(id)pId
{
    running = false;
}

- (IBAction)closeButtonPushed:(id)pId
{
    [_popup setIsVisible:FALSE];
}

- (void)auto_select_algorithms:(char *)c : (char *)h : (char *)m
{
    const char **ciphers = list_of_ciphers();
    unsigned slctd_cipher = 0;
    [_cipherCombo removeAllItems];
    [_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_CIPHER]];
    for (unsigned i = 0; ciphers[i]; i++)
    {
        if (c && !strcasecmp(ciphers[i], c))
            slctd_cipher = i + 1;
        [_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:ciphers[i]]];
    }
    [_cipherCombo selectItemAtIndex:slctd_cipher];

    const char **hashes = list_of_hashes();
    unsigned slctd_hash = 0;
    [_hashCombo removeAllItems];
    [_hashCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_HASH]];
    for (unsigned  i = 0; hashes[i]; i++)
    {
        if (h && !strcasecmp(hashes[i], h))
            slctd_hash = i + 1;
        [_hashCombo addItemWithTitle:[NSString stringWithUTF8String:hashes[i]]];
    }
    [_hashCombo selectItemAtIndex:slctd_hash];

    const char **modes = list_of_modes();
    unsigned slctd_mode = 0;
    [_modeCombo removeAllItems];
    [_modeCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_MODE]];
    for (unsigned  i = 0; modes[i]; i++)
    {
        if (m && !strcasecmp(modes[i], m))
            slctd_mode = i + 1;
        [_modeCombo addItemWithTitle:[NSString stringWithUTF8String:modes[i]]];
    }
    [_modeCombo selectItemAtIndex:slctd_mode];
}

@end
