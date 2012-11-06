/*
 * encrypt ~ a simple, modular, (multi-OS,) encryption utility
 * Copyright © 2005-2012, albinoloverats ~ Software Development
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

#import "AppDelegate.h"

#import "common.h"
#import "error.h"
#import "encrypt.h"

@implementation AppDelegate

extern char *FAILED_MESSAGE[];

static void *bg_thread_gui(void *arg);

static bool encrypted = true;
static bool compress = true;
static status_e status = PREPROCESSING;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    char **ciphers = get_algorithms_crypt();
    unsigned slctd_cipher = 0;
    for (unsigned i = 0; ; i++)
    {
        if (!ciphers[i])
            break;
#if 0
        /*
         * TODO check rc file for default/preset algorithms
         */
        else if (cipher && !strcasecmp(ciphers[i], cipher))
        {
            slctd_cipher = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is algorithm: %s"), slctd_cipher, cipher);
        }
#endif
        [_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:ciphers[i]]];
        free(ciphers[i]);
    }
    [_cipherCombo selectItemAtIndex:slctd_cipher];
    free(ciphers);

    char **hashes = get_algorithms_hash();
    unsigned slctd_hash = 0;
    for (unsigned  i = 0; ; i++)
    {
        if (!hashes[i])
            break;
#if 0
        /*
         * ditto above
         */
        else if (hash && !strcasecmp(hashes[i], hash))
        {
            slctd_hash = i + 1;
            log_message(LOG_VERBOSE, _("Selected %d is hash: %s"), slctd_hash, hash);
        }
#endif
        [_hashCombo addItemWithTitle:[NSString stringWithUTF8String:hashes[i]]];
        free(hashes[i]);
    }
    [_cipherCombo selectItemAtIndex:slctd_hash];
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

    [_statusBar setStringValue:@STATUS_READY];

    return;
}

- (IBAction)compressionToggle:(id)pId
{
    compress = !(bool)[_compress state];
    [_compress setState:compress];
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
    int f = open(open_file, O_RDONLY, S_IRUSR | S_IWUSR);
    free(open_file);
    if (f < 0)
        goto clean_up;
    encrypted = file_encrypted(f);
    [_encryptButton setTitle: encrypted ? @LABEL_DECRYPT : @LABEL_ENCRYPT];
    close(f);

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
    if (errno != ENOENT && !S_ISREG(s.st_mode))
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

    [self performSelectorInBackground:@selector(bg_thread_gui:) withObject:nil];

    uint64_t sz = 0;

    do
    {
        if (!sz)
            sz = get_decrypted_size();
        else
        {
            uint64_t bp = get_bytes_processed();
            [_progress setDoubleValue:100 * bp / sz];
        }
        status = get_status();
    }
    while (status == RUNNING);

    char *msg = NULL;

    if (status == SUCCEEDED)
    {
        [_progress setDoubleValue:100.0];
        msg = STATUS_DONE;
    }
    else
        msg = FAILED_MESSAGE[status];

    [_statusBar setStringValue:[NSString stringWithUTF8String:msg]];
    [_closeButton setHidden:FALSE];
    [_cancelButton setHidden:TRUE];
}

- (void)bg_thread_gui:(id)pId
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

    int64_t source = open(open_file, O_RDONLY | O_BINARY | F_RDLCK, S_IRUSR | S_IWUSR);
    int64_t output = open(save_file, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | F_WRLCK, S_IRUSR | S_IWUSR);

    free(open_file);
    free(save_file);

    /*
     * get raw key data
     */
    raw_key_t key = {NULL, 0, NULL, 0};
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
            status = FAILED_OTHER;
            return;
        }
        key.p_length = lseek(kf, 0, SEEK_END);
        key.p_data = malloc(key.p_length);
        if (!key.p_data)
            die(_("Out of memory @ %s:%d:%s [%" PRIu64 "]"), __FILE__, __LINE__, __func__, key.p_length);
        read(kf, key.p_data, key.p_length);
        close(kf);

    }
    else
    {
        key.p_data = (uint8_t *)strdup([[_passwordField stringValue] UTF8String]);
        key.p_length = strlen((char *)key.p_data);
    }

    encrypt_t e_data = { NULL, NULL, key, true, compress };

    if (!encrypted)
    {
        e_data.cipher = (char *)[[[_cipherCombo selectedItem] title] UTF8String];
        e_data.hash = (char *)[[[_hashCombo selectedItem] title] UTF8String];

        status = main_encrypt(source, output, e_data);
    }
    else
        status = main_decrypt(source, output, e_data);

    close(source);
    close(output);

    free(key.p_data);

    return;
}

- (IBAction)cancelButtonPushed:(id)pId
{
    stop_running();
}

- (IBAction)closeButtonPushed:(id)pId
{
    [_popup setIsVisible:FALSE];
}

@end