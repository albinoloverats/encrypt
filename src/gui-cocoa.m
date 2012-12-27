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

#import <sys/stat.h>
#import <sys/time.h>

#import <math.h>

#import "gui.h"
#import "gui-cocoa.h"

#import "common.h"
#import "version.h"
#import "error.h"

#import "crypto.h"
#import "encrypt.h"
#import "decrypt.h"
#import "init.h"
#import "cli.h"

@implementation AppDelegate

static bool encrypted = true;
static bool compress = true;
static bool running = false;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    version_check_for_update(ENCRYPT_VERSION, UPDATE_URL);

    args_t args = init(0, NULL);

    char **ciphers = list_of_ciphers();
    unsigned slctd_cipher = 0;
    for (unsigned i = 0; ; i++)
    {
        if (!ciphers[i])
            break;
        /*
         * TODO check rc file for default/preset algorithms
         */
        else if (args.cipher && !strcasecmp(ciphers[i], args.cipher))
            slctd_cipher = i + 1;
        [_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:ciphers[i]]];
        free(ciphers[i]);
    }
    [_cipherCombo selectItemAtIndex:slctd_cipher];
    free(ciphers);

    char **hashes = list_of_hashes();
    unsigned slctd_hash = 0;
    for (unsigned  i = 0; ; i++)
    {
        if (!hashes[i])
            break;
        /*
         * ditto above
         */
        else if (args.hash && !strcasecmp(hashes[i], args.hash))
            slctd_hash = i + 1;
        [_hashCombo addItemWithTitle:[NSString stringWithUTF8String:hashes[i]]];
        free(hashes[i]);
    }
    [_hashCombo selectItemAtIndex:slctd_hash];
    free(hashes);

    long i = [_sourceFileChooser numberOfItems];
    bool z = true;
    for (int j = 0, k = 0; j < i; j++, k++)
    {
        const char *t = [[_sourceFileChooser itemTitleAtIndex:k] UTF8String];
        
        if (!strcmp(t, SELECT_FILE))
            continue;
        else if (z && !strcmp(t, ""))
        {
            z = false;
            continue;
        }
        else if (!strcmp(t, SELECT_OTHER))
            continue;
        [_sourceFileChooser removeItemAtIndex:k];
        k--;
    }

    i = [_outputFileChooser numberOfItems];
    z = true;
    for (int j = 0, k = 0; j < i; j++, k++)
    {
        const char *t = [[_outputFileChooser itemTitleAtIndex:k] UTF8String];

        if (!strcmp(t, SELECT_FILE))
            continue;
        else if (z && !strcmp(t, ""))
        {
            z = false;
            continue;
        }
        else if (!strcmp(t, SELECT_NEW))
            continue;

        else if (!strcmp(t, SELECT_OTHER))
            continue;
        [_outputFileChooser removeItemAtIndex:k];
        k--;
    }

    i = [_keyFileChooser numberOfItems];
    z = true;
    for (int j = 0, k = 0; j < i; j++, k++)
    {
        const char *t = [[_keyFileChooser itemTitleAtIndex:k] UTF8String];

        if (!strcmp(t, SELECT_KEY))
            continue;
        else if (z && !strcmp(t, ""))
        {
            z = false;
            continue;
        }
        else if (!strcmp(t, SELECT_OTHER))
            continue;
        [_keyFileChooser removeItemAtIndex:k];
        k--;
    }

    [_compress setState:args.compress];

    [_statusBar setStringValue:@STATUS_BAR_READY];

    return;
}

- (IBAction)compressionToggle:(id)pId
{
    compress = !(bool)[_compress state];
    [_compress setState:compress];
    update_config(CONF_COMPRESS, compress ? CONF_TRUE : CONF_FALSE);
}

- (IBAction)ioFileChoosen:(id)pId
{
    Boolean en = FALSE;
    const char *open_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@"sourceFile"] UTF8String];
    const char *save_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@"outputFile"] UTF8String];

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
    encrypted = file_encrypted(open_file);
    [_encryptButton setTitle: encrypted ? @LABEL_DECRYPT : @LABEL_ENCRYPT];

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

    [_cipherCombo setEnabled:(en)];
    [_hashCombo setEnabled:(en)];
}

- (IBAction)cipherHashSelected:(id)pId
{
    if (([[[_cipherCombo selectedItem] title] isEqualTo:@SELECT_CIPHER])
        || ([[[_hashCombo selectedItem] title] isEqualTo:@SELECT_HASH]))
    {
        // Unselected either cipher/hash, disable all options below
        [_keyCombo setEnabled:(FALSE)];
        [_keyFileChooser setEnabled:(FALSE)];
        [_passwordField setEnabled:(FALSE)];
        [_encryptButton setEnabled:(FALSE)];
    }
    else
    {
        [_keyCombo setEnabled:(TRUE)];
        [self keySourceSelected:(pId)];
    }
}

- (IBAction)keySourceSelected:(id)pId
{
    Boolean k = FALSE;
    Boolean p = FALSE;
    Boolean h = TRUE;
    if ([[[_keyCombo selectedItem] title] isEqualToString:@KEY_FILE])
        k = TRUE, h = FALSE;
    else if([[[_keyCombo selectedItem] title] isEqualToString:@PASSPHRASE])
        p = TRUE, h = FALSE;
    // Enable/disable as necessary; show/hide too (keep most recent visible)
    [_keyFileChooser setEnabled:(k)];
    [_keyFileChooserButton setHidden:(!k)];
    [_passwordField setEnabled:(p)];
    [_passwordField setHidden:(!p ^ h)];
    // See if the action button needs changing
    if (k)
        ;//[self keyFileChoosen:(pId)];
    else if (p)
        [self passwordFieldUpdated:(pId)];
    else
        [_encryptButton setEnabled:(FALSE)];
}

- (IBAction)keyFileChoosen:(id)pId
{
    const char *key_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] UTF8String];
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
    
    [_encryptButton setEnabled:(en)];
}

- (IBAction)passwordFieldUpdated:(id)pId
{
    // Toggle encrypt/decrypt button based on passphrase length
    if ([[_passwordField stringValue] length] > 0)
        [_encryptButton setEnabled:(TRUE)];
    else
        [_encryptButton setEnabled:(FALSE)];
}


- (IBAction)encryptButtonPushed:(id)pId
{
    [_popup setIsVisible:TRUE];
    [_progress_current setHidden:FALSE];
    [_percent_current setHidden:FALSE];

    [self performSelectorInBackground:@selector(display_gui:) withObject:nil];
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
    if ([[[_keyCombo selectedItem] title] isEqualToString:@KEY_FILE])
    {
        const char *key_link = [[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] UTF8String];

        char *key_file = NULL;
        if (key_link[0] == '~')
            asprintf(&key_file, "%s/%s", getenv("HOME"), key_link + 1);
        else
            key_file = strdup(key_link);

        int64_t kf = open(key_file, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
        free(key_file);
        if (kf < 0)
        {
            /*
             * TODO implement some error handling
             */
            return;
        }
        length = lseek(kf, 0, SEEK_END);
        lseek(kf, 0, SEEK_SET);
        if (!(key = malloc(length)))
            die("Out of memory @ %s:%d:%s [%" PRIu64 "]", __FILE__, __LINE__, __func__, length);
        read(kf, key, length);
        close(kf);
    }
    else
    {
        key = (uint8_t *)strdup([[_passwordField stringValue] UTF8String]);
        length = strlen((char *)key);
    }

    crypto_t *c;
    if (!encrypted)
        c = encrypt_init(open_file, save_file, (char *)[[[_cipherCombo selectedItem] title] UTF8String], (char *)[[[_hashCombo selectedItem] title] UTF8String], key, length, compress);
    else
        c = decrypt_init(open_file, save_file, key, length);

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
        if (isnan(val))
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
            else
                asprintf(&bps_label, "%5.1f TB/s", val / TERABYTE);
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

@end