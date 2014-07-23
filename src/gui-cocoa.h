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

#import <Cocoa/Cocoa.h>
#import <Automator/Automator.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

#define SELECT_FILE "Select File…"
#define SELECT_NEW "New…"
#define SELECT_OTHER "Other…"
#define SELECT_KEY "Select Key…"

#define SOURCE_FILE "sourceFile"
#define OUTPUT_FILE "outputFile"
#define KEYSRC_FILE "keyFile"

/*
 * main window
 */
@property (assign) IBOutlet NSWindow *window;

@property (strong, nonatomic) IBOutlet NSMenuItem *compress;
@property (strong, nonatomic) IBOutlet NSMenuItem *follow;
@property (strong, nonatomic) IBOutlet NSMenuItem *raw;
@property (strong, nonatomic) IBOutlet NSMenu *version;

@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *sourceFileChooser;
@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *outputFileChooser;

@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *cipherCombo;
@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *hashCombo;
@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *modeCombo;

@property (strong, nonatomic) IBOutlet NSMenu *keySource;
@property (strong, nonatomic) IBOutlet NSMenuItem *keySourceFile;
@property (strong, nonatomic) IBOutlet NSMenuItem *keySourcePassword;

@property (strong, nonatomic) IBOutlet NSPopUpButton *keyFileChooserButton;
@property (strong, nonatomic) IBOutlet NSPopUpButtonCell *keyFileChooser;
@property (strong, nonatomic) IBOutlet NSSecureTextField *passwordField;

@property (strong, nonatomic) IBOutlet NSButton *singleButton;
@property (strong, nonatomic) IBOutlet NSButton *encryptButton;
@property (strong, nonatomic) IBOutlet NSButton *decryptButton;

@property (strong, nonatomic) IBOutlet NSTextField *statusBar;

/*
 * progress dialog
 */

@property (assign) IBOutlet NSPanel *popup;

@property (strong, nonatomic) IBOutlet NSButton *cancelButton;
@property (strong, nonatomic) IBOutlet NSButton *closeButton;
@property (strong, nonatomic) IBOutlet NSProgressIndicator *progress_total;
@property (strong, nonatomic) IBOutlet NSTextField *percent_total;
@property (strong, nonatomic) IBOutlet NSProgressIndicator *progress_current;
@property (strong, nonatomic) IBOutlet NSTextField *percent_current;
@property (strong, nonatomic) IBOutlet NSTextField *progress_label;

/*
 * callbacks
 */

- (IBAction)compressionToggle:(id)pId;
- (IBAction)followToggle:(id)pId;
- (IBAction)versionToggle:(id)pId;


- (IBAction)ioFileChoosen:(id)pId;
- (IBAction)keyFileChoosen:(id)pId;
- (IBAction)passwordFieldUpdated:(id)pId;
- (IBAction)encryptButtonPushed:(id)pId;

- (IBAction)cancelButtonPushed:(id)pId;
- (IBAction)closeButtonPushed:(id)pId;

@end
