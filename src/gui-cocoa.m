/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2022, albinoloverats ~ Software Development
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
#import "cli.h"
#import "version.h"
#import "error.h"
#import "ccrypt.h"
#import "config.h"
#import "list.h"

#import "crypt.h"
#import "encrypt.h"
#import "decrypt.h"

@implementation AppDelegate

char *KEY_SOURCE[] =
{
	"file",
	"password"
};

#if 0
char *gui_file_hack_source = NULL;
char *gui_file_hack_output = NULL;
#endif

static char *source = NULL;
static char *output = NULL;
static char *key_file = NULL;
static bool encrypted = true;
static bool compress = true;
static bool follow = false;
static bool raw = false;
static bool running = false;
static version_e version = VERSION_CURRENT;
static key_source_e key_source = KEY_SOURCE_PASSWORD;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
	version_check_for_update(ENCRYPT_VERSION, UPDATE_URL, DOWNLOAD_URL_TEMPLATE);

	config_about_t about =
	{
		NULL,
		ENCRYPT_VERSION,
		PROJECT_URL,
		ENCRYPTRC
	};
	config_init(about);

	LIST args = list_init(config_arg_comp, false, false);
	// TODO If there's no CLI then remove the display text
	list_add(args, &((config_arg_t){ 'c', "cipher",         _("algorithm"),  _("Algorithm to use to encrypt data; use ‘list’ to show available cipher algorithms"),                                      CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 's', "hash",           _("algorithm"),  _("Hash algorithm to generate key; use ‘list’ to show available hash algorithms"),                                          CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 'm', "mode",           _("mode"),       _("The encryption mode to use; use ‘list’ to show available cipher modes"),                                                 CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 'a', "mac",            _("mac"),        _("The MAC algorithm to use; use ‘list’ to show available MACs"),                                                           CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 'i', "kdf-iterations", _("iterations"), _("Number of iterations the KDF should use"),                                                                               CONFIG_ARG_REQ_NUMBER,  { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 0x1, "key-source",     _("key source"), _("Key data source"),                                                                                                       CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, true  }));
	list_add(args, &((config_arg_t){ 0x2, "compress",       NULL,            _("Compress the plain text using the xz algorithm"),                                                                        CONFIG_ARG_REQ_STRING,  { 0x0 }, false, false, true  }));
	list_add(args, &((config_arg_t){ 'f', "follow",         NULL,            _("Follow symlinks, the default is to store the link itself"),                                                              CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, false, false }));
	list_add(args, &((config_arg_t){ 'b', "back-compat",    _("version"),    _("Create an encrypted file that is backwards compatible"),                                                                 CONFIG_ARG_REQ_STRING,  { 0x0 }, false, true,  false }));
	list_add(args, &((config_arg_t){ 'r', "raw",            NULL,            _("Don’t generate or look for an encrypt header; this IS NOT recommended, but can be useful in some (limited) situations"), CONFIG_ARG_REQ_BOOLEAN, { 0x0 }, false, true, false  }));
	config_parse(0, NULL, args);

	char *cipher =  ((config_arg_t *)list_get(args, 0))->response_value.string;
	char *hash   =  ((config_arg_t *)list_get(args, 1))->response_value.string;
	char *mode   =  ((config_arg_t *)list_get(args, 2))->response_value.string;
	char *mac    =  ((config_arg_t *)list_get(args, 3))->response_value.string;
	uint64_t kdf =  ((config_arg_t *)list_get(args, 4))->response_value.number;

	char *ks     =  ((config_arg_t *)list_get(args, 5))->response_value.string;

	compress     = !((config_arg_t *)list_get(args, 6))->response_value.boolean; // compress by default unless --no-compress is specified
	follow       =  ((config_arg_t *)list_get(args, 7))->response_value.boolean;

	char *ver    =  ((config_arg_t *)list_get(args, 8))->response_value.string;
	raw          =  ((config_arg_t *)list_get(args, 9))->response_value.boolean;

	[self auto_select_algorithms:cipher:hash:mode:mac:kdf];

#if 0
	if (gui_file_hack_source)
	{
		[_sourceFileChooser addItemWithTitle:[NSString stringWithUTF8String:basename(gui_file_hack_source)]];
		[NSUserDefaults.standardUserDefaults setValue:[NSUserDefaults.standardUserDefaults valueForKeyPath:@SOURCE_FILE] forKeyPath:[NSString stringWithUTF8String:gui_file_hack_source]];
	}

	if (gui_file_hack_output)
	{
		[_outputFileChooser addItemWithTitle:[NSString stringWithUTF8String:gui_file_hack_output]];
		[NSUserDefaults.standardUserDefaults setValue:[NSUserDefaults.standardUserDefaults valueForKeyPath:@OUTPUT_FILE] forKeyPath:[NSString stringWithUTF8String:gui_file_hack_output]];
	}
#endif

	/* set menu options based of config settings */
	[_compress setState:compress];

	[_follow setState:follow];

	[_raw setState:raw];
	[self toggleButtons];

	version = parse_version(ver);
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

	if (ks && !strcasecmp(ks, "file"))
		key_source = KEY_SOURCE_FILE;
	[self keySourceToggle];

	[_statusBar setStringValue:@STATUS_BAR_READY];

	return;
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication
{
	return YES;
}

- (IBAction)compressionToggle:(id)pId
{
	compress = !(bool)[_compress state];
	[_compress setState:compress];
	update_config(CONF_COMPRESS, compress ? CONF_TRUE : CONF_FALSE);
}

- (IBAction)rawToggle:(id)pId
{
	raw = !(bool)[_raw state];
	[_raw setState:raw];
	update_config(CONF_SKIP_HEADER, raw ? CONF_TRUE : CONF_FALSE);

	[self toggleButtons];
}

- (void)toggleButtons
{
	[_singleButton setHidden:raw];
	[_encryptButton setHidden:!raw];
	[_decryptButton setHidden:!raw];
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

- (IBAction)ioSourceChoosen:(id)pId
{
	NSOpenPanel *panel = [NSOpenPanel openPanel];
	[panel setTitle:@"Open ..."];
	[panel setCanChooseFiles:YES];
	[panel setCanChooseDirectories:YES];
	[panel setCanCreateDirectories:NO];
	[panel setAllowsMultipleSelection:NO];

	NSInteger clicked = [panel runModal];

	if (source)
	{
		free(source);
		source = NULL;
	}

	if (clicked == NSFileHandlingPanelOKButton)
	{
		NSString *name = [[[panel URL] filePathURL] lastPathComponent];
		source = strdup((char *)[[[panel URL] filePathURL] fileSystemRepresentation]);
		[_sourceFileButton setTitle:name];
	}
	else
		[_sourceFileButton setTitle:@"Source"];

	[self ioFileChoosen:pId];
}

- (IBAction)ioOutputChoosen:(id)pId
{
	NSSavePanel *panel = [NSSavePanel savePanel];
	[panel setTitle:@"Save As ..."];
	[panel setCanCreateDirectories:YES];

	NSInteger clicked = [panel runModal];

	if (output)
	{
		free(output);
		output = NULL;
	}

	if (clicked == NSFileHandlingPanelOKButton)
	{
		NSString *name = [[[panel URL] filePathURL] lastPathComponent];
		output = strdup((char *)[[[panel URL] filePathURL] fileSystemRepresentation]);
		[_outputFileButton setTitle:name];
	}
	else
		[_outputFileButton setTitle:@"Destination"];

	[self ioFileChoosen:pId];
}

- (IBAction)ioFileChoosen:(id)pId
{
	Boolean en = FALSE;

	if (!source || !strlen(source))
		goto clean_up;

	char *open_file = NULL;
	if (source[0] == '~')
		asprintf(&open_file, "%s/%s", getenv("HOME"), source + 1);
	else
		open_file = strdup(source);
	/*
	 * check if the file is encrypted or not
	 */
	void *ptr = malloc(0);
	char *c = ptr;
	char *h = ptr;
	char *m = ptr;
	char *a = ptr;
	uint64_t i;
	if ((encrypted = is_encrypted(open_file, &c, &h, &m, &a, &i)))
	{
		[self auto_select_algorithms:c:h:m:a:i];
		free(c);
		free(h);
		free(m);
		free(a);
	}
	free(ptr);
	free(open_file);
	[_singleButton setTitle:encrypted ? @LABEL_DECRYPT : @LABEL_ENCRYPT];

	if (!output || !strlen(output))
		goto clean_up;

	char *save_file = NULL;
	if (output[0] == '~')
		asprintf(&save_file, "%s/%s", getenv("HOME"), output + 1);
	else
		save_file = strdup(output);
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

	[self cipherHashSelected:pId];

	if (!encrypted)
	{
		[_cipherCombo setEnabled:en];
		[_hashCombo setEnabled:en];
		[_modeCombo setEnabled:en];
		[_macCombo setEnabled:en];
		[_kdfIterations setEnabled:en];
		[_kdfIterate setEnabled:en];
	}
	else
	{
		[_cipherCombo setEnabled:FALSE];
		[_hashCombo setEnabled:FALSE];
		[_modeCombo setEnabled:FALSE];
		[_macCombo setEnabled:FALSE];
		[_kdfIterations setEnabled:FALSE];
		[_kdfIterate setEnabled:FALSE];
	}
}

- (IBAction)cipherHashSelected:(id)pId
{
	const char *cipher = [[[_cipherCombo selectedItem] title] UTF8String];
	const char *hash = [[[_hashCombo selectedItem] title] UTF8String];
	const char *mode = [[[_modeCombo selectedItem] title] UTF8String];
	const char *mac = [[[_macCombo selectedItem] title] UTF8String];
	uint64_t iter = [_kdfIterations intValue];
	[_kdfIterate setIntValue:[_kdfIterations intValue]];

	bool mode_okay = mode_valid_for_cipher(cipher_id_from_name(cipher), mode_id_from_name(mode));

	if (source && output && (cipher && strcasecmp(cipher, SELECT_CIPHER)) && (hash && strcasecmp(hash, SELECT_HASH)) && (mode && strcasecmp(mode, SELECT_MODE)) && (mac && strcasecmp(mac, SELECT_MAC)) && iter && mode_okay)
	{
		[self keySourceSelected:pId];
		[_keyFileChooser setEnabled:true];
		[_keyFileButton setEnabled:true];
		[_passwordField setEnabled:true];

		update_config(CONF_CIPHER, cipher);
		update_config(CONF_HASH, hash);
		update_config(CONF_MODE, mode);
		update_config(CONF_MAC, mac);
		char kdf[22];
		snprintf(kdf, sizeof kdf, "%" PRIu64, iter);
		update_config(CONF_KDF_ITERATIONS, kdf);
	}
	else
	{
		// Unselected either cipher/hash/mode, disable all options below
		[_keyFileChooser setEnabled:false];
		[_keyFileButton setEnabled:false];
		[_passwordField setEnabled:false];
		[_singleButton setEnabled:false];
		[_encryptButton setEnabled:false];
		[_decryptButton setEnabled:false];
	}

	[_statusBar setStringValue: mode_okay ? @STATUS_BAR_READY : @STATUS_BAD_MODE];
}

- (IBAction)kdfStepperPushed:(id)pId
{
	[_kdfIterations setIntValue:[_kdfIterate intValue]];
	[self cipherHashSelected:pId];
	return;
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
	update_config(CONF_KEY_SOURCE, KEY_SOURCE[key_source]);
	[self keySourceToggle];
}

- (void)keySourceToggle
{
	[_keySourceFile setState:key_source == KEY_SOURCE_FILE ? NSOnState : NSOffState];
	[_keySourcePassword setState:key_source == KEY_SOURCE_PASSWORD ? NSOnState : NSOffState];

	[_keyFileButton setHidden:key_source != KEY_SOURCE_FILE];
	[_passwordField setHidden:key_source != KEY_SOURCE_PASSWORD];
}

- (IBAction)keyFileChoosen:(id)pId
{
	NSOpenPanel *panel = [NSOpenPanel openPanel];
	[panel setTitle:@"Select key ..."];
	[panel setCanChooseFiles:YES];
	[panel setCanChooseDirectories:NO];
	[panel setCanCreateDirectories:NO];
	[panel setAllowsMultipleSelection:NO];

	NSInteger clicked = [panel runModal];

	if (key_file)
	{
		free(key_file);
		key_file = NULL;
	}

	BOOL en = FALSE;
	if (clicked == NSFileHandlingPanelOKButton)
	{
		NSString *name = [[[panel URL] filePathURL] lastPathComponent];
		key_file = strdup((char *)[[[panel URL] filePathURL] fileSystemRepresentation]);
		[_keyFileButton setTitle:name];
		en = TRUE;
	}
	else
		[_keyFileButton setTitle:@"Select Key ..."];

	[_singleButton setEnabled:en];
	[_encryptButton setEnabled:en];
	[_decryptButton setEnabled:en];
}

- (IBAction)passwordFieldUpdated:(id)pId
{
	// Toggle encrypt/decrypt button based on passphrase length
	[_singleButton setEnabled:([[_passwordField stringValue] length] > 0)];
	[_encryptButton setEnabled:([[_passwordField stringValue] length] > 0)];
	[_decryptButton setEnabled:([[_passwordField stringValue] length] > 0)];
}


- (IBAction)encryptButtonPushed:(id)pId
{
	[_popup setIsVisible:TRUE];
	[_popup setAllowsConcurrentViewDrawing:YES];

	[_progress_current setHidden:FALSE];
	[_percent_current setHidden:FALSE];

	[self performSelectorInBackground:@selector(display_gui:)withObject:pId];
}

- (void)display_gui:(id)pId
{
	/*
	 * get raw key data
	 */
	uint8_t *key;
	size_t length;
	if (key_source == KEY_SOURCE_FILE)
	{
		key = (uint8_t *)key_file;
		length = 0;
	}
	else
	{
		key = (uint8_t *)[[_passwordField stringValue] UTF8String];
		length = strlen((char *)key);
	}

	if (raw && _encryptButton == pId)
		encrypted = false;
	else if (raw && _decryptButton == pId)
		encrypted = true;

	char *cipher = (char *)[[[_cipherCombo selectedItem] title] UTF8String];
	char *hash = (char *)[[[_hashCombo selectedItem] title] UTF8String];
	char *mode = (char *)[[[_modeCombo selectedItem] title] UTF8String];
	char *mac = (char *)[[[_macCombo selectedItem] title] UTF8String];
	uint64_t iter = [_kdfIterations intValue];

	crypto_t *c;
	if (!encrypted)
		c = encrypt_init(source, output, cipher, hash, mode, mac, key, length, iter, raw, compress, follow, version);
	else
		c = decrypt_init(source, output, cipher, hash, mode, mac, key, length, iter, raw);

	dispatch_time_t oneSecond = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(NSEC_PER_SEC));

	if (c->status != STATUS_INIT)
		goto tidy;

	running = true;
	execute(c);

	cli_bps_t bps[BPS];
	memset(bps, 0x00, BPS * sizeof( cli_bps_t ));
	int b = 0;

	while (c->status == STATUS_INIT || c->status == STATUS_RUNNING)
	{
		if (!running)
			c->status = STATUS_CANCELLED;

		struct timespec s = { 0, MILLION };
		nanosleep(&s, NULL);

		if (c->status == STATUS_INIT)
			continue;

		dispatch_after(oneSecond, dispatch_get_main_queue(), ^{
			double pc = (PERCENT * c->total.offset + PERCENT * c->current.offset / c->current.size) / c->total.size;
			if (c->total.offset == c->total.size)
				pc = PERCENT * c->total.offset / c->total.size;
			[self.progress_total setDoubleValue:pc];

			char tpc[7];
			snprintf(tpc, sizeof tpc, "%3.0f %%", pc);
			[self.percent_total setStringValue:[NSString stringWithUTF8String:tpc]];
		});

		if (c->total.size == 1)
		{
			[_progress_current setHidden:TRUE];
			[_percent_current setHidden:TRUE];
		}
		else
		{
			dispatch_after(oneSecond, dispatch_get_main_queue(), ^{
				double cp = PERCENT * c->current.offset / c->current.size;
				[self.progress_current setDoubleValue:cp];

				char name[CLI_TRUNCATED_DISPLAY_LONG] = { 0x0 };
				char *nm = c->current.display ? c->current.display : CLI_UNKNOWN;
				if (strlen(nm) < CLI_TRUNCATED_DISPLAY_LONG)
					strcpy(name, nm);
				else
				{
					strncpy(name, nm, CLI_TRUNCATED_DISPLAY_SHORT);
					strcat(name, CLI_TRUNCATED_ELLIPSE);
					strcat(name, nm + (strlen(nm) - CLI_TRUNCATED_DISPLAY_SHORT));
				}

				char cpc[CLI_TRUNCATED_DISPLAY_LONG * 2];
				snprintf(cpc, sizeof cpc, "%s%s%3.0f %%", c->current.display ? name : "", c->current.display ? " : " : "", cp);
				[self.percent_current setStringValue:[NSString stringWithUTF8String:cpc]];
			});
		}

		struct timeval tv;
		gettimeofday(&tv, NULL);
		bps[b].time = tv.tv_sec * MILLION + tv.tv_usec;
		bps[b].bytes = c->current.offset;
		double val = cli_calc_bps(bps);
		b++;
		if (b >= BPS)
			b = 0;

		dispatch_after(oneSecond, dispatch_get_main_queue(), ^{
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
//                else
//                    asprintf(&bps_label, "%5.1f TB/s", val / TERABYTE);
			}
			if (bps_label)
				[self.progress_label setStringValue:[NSString stringWithUTF8String:bps_label]];
			free(bps_label);
		});
	}

tidy:
	dispatch_after(oneSecond, dispatch_get_main_queue(), ^{
		[self.progress_label setStringValue:[NSString stringWithUTF8String:status(c)]];
	});
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

- (void)auto_select_algorithms:(char *)c : (char *)h : (char *)m : (char *)a : (uint64_t)iter
{
	LIST ciphers = list_of_ciphers();
	unsigned slctd_cipher = 0;
	[_cipherCombo removeAllItems];
	[_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_CIPHER]];
	for (unsigned i = 0; i < list_size(ciphers); i++)
	{
		const char *cipher = list_get(ciphers, i);
		if (c && !strcasecmp(cipher, c))
			slctd_cipher = i + 1;
		[_cipherCombo addItemWithTitle:[NSString stringWithUTF8String:cipher]];
	}
	[_cipherCombo selectItemAtIndex:slctd_cipher];

	LIST hashes = list_of_hashes();
	unsigned slctd_hash = 0;
	[_hashCombo removeAllItems];
	[_hashCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_HASH]];
	for (unsigned  i = 0; i < list_size(hashes); i++)
	{
		const char *hash = list_get(hashes, i);
		if (h && !strcasecmp(hash, h))
			slctd_hash = i + 1;
		[_hashCombo addItemWithTitle:[NSString stringWithUTF8String:hash]];
	}
	[_hashCombo selectItemAtIndex:slctd_hash];

	LIST modes = list_of_modes();
	unsigned slctd_mode = 0;
	[_modeCombo removeAllItems];
	[_modeCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_MODE]];
	for (unsigned  i = 0; i < list_size(modes); i++)
	{
		const char *mode = list_get(modes, i);
		if (m && !strcasecmp(mode, m))
			slctd_mode = i + 1;
		[_modeCombo addItemWithTitle:[NSString stringWithUTF8String:mode]];
	}
	[_modeCombo selectItemAtIndex:slctd_mode];

	LIST macs = list_of_macs();
	unsigned slctd_mac = 0;
	[_macCombo removeAllItems];
	[_macCombo addItemWithTitle:[NSString stringWithUTF8String:SELECT_MAC]];
	for (unsigned  i = 0; i < list_size(macs); i++)
	{
		const char *mac = list_get(macs, i);
		if (h && !strcasecmp(mac, a))
			slctd_mac = i + 1;
		[_macCombo addItemWithTitle:[NSString stringWithUTF8String:mac]];
	}
	[_macCombo selectItemAtIndex:slctd_mac];

	[_kdfIterations setIntValue:(int)iter];
	[_kdfIterate setIntValue:(int)iter];
}

@end
