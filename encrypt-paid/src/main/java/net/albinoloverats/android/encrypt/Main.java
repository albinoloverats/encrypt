/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2025, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Dialog;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.NumberPicker;
import android.widget.Spinner;
import android.widget.Toast;
import androidx.core.app.ActivityCompat;
import androidx.documentfile.provider.DocumentFile;
import com.simaomata.DoubleProgressDialog;
import lombok.RequiredArgsConstructor;
import lombok.val;
import net.albinoloverats.android.encrypt.lib.FileAction;
import net.albinoloverats.android.encrypt.lib.Options;
import net.albinoloverats.android.encrypt.lib.ProgressUpdate;
import net.albinoloverats.android.encrypt.lib.crypt.Crypto;
import net.albinoloverats.android.encrypt.lib.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.lib.crypt.Decrypt;
import net.albinoloverats.android.encrypt.lib.crypt.Encrypt;
import net.albinoloverats.android.encrypt.lib.crypt.Status;
import net.albinoloverats.android.encrypt.lib.crypt.Version;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Set;

import static net.albinoloverats.android.encrypt.lib.IntentKey.*;

public class Main extends Activity
{
	private static final Set<String> CIPHERS = CryptoUtils.getCipherAlgorithmNames();
	private static final Set<String> HASHES = CryptoUtils.getHashAlgorithmNames();
	private static final Set<String> MODES = CryptoUtils.getCipherModeNames();
	private static final Set<String> MACS = CryptoUtils.getMacAlgorithmNames();

	private static final String[] STORAGE_PERMISSIONS =
		{
			Manifest.permission.READ_EXTERNAL_STORAGE,
			Manifest.permission.WRITE_EXTERNAL_STORAGE
		};
	private static final int STORAGE_PERMISSION_REQUEST = 1;

	private DoubleProgressDialog doubleProgressDialog;
	private ProgressReceiver progressReceiver;
	private MessageHandler messageHandler;

	private boolean compress = true;
	private boolean follow = false;
	private boolean key_file = false;
	private boolean raw = false;
	private Version version = Version.CURRENT;

	private ArrayList<Uri> filenamesIn;
	private Uri filenameOut;
	private boolean encrypting = true;
	private String cipher;
	private String hash;
	private String mode;
	private String mac;
	private int kdfIterations;
	private String password;
	private Uri key;

	//private boolean cancel = false;

	@Override
	public void onCreate(final Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		checkPermissions();

		val settings = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), Context.MODE_PRIVATE);
		cipher = settings.getString(Options.CIPHER.toString(), null);
		hash = settings.getString(Options.HASH.toString(), null);
		mode = settings.getString(Options.MODE.toString(), null);
		mac = settings.getString(Options.MAC.toString(), null);
		kdfIterations = settings.getInt(Options.KDF_ITERATIONS.toString(), Crypto.KDF_ITERATIONS_DEFAULT);

		// set up the file chooser button
		val fChooser = findViewById(R.id.button_file);
		fChooser.setOnClickListener(new FileChooserListener(FileAction.LOAD));

		// set up the file output chooser button
		findViewById(R.id.button_output).setOnClickListener(new FileChooserListener(FileAction.SAVE));

		// set up the hash and crypto spinners
		val cSpinner = (Spinner)findViewById(R.id.spin_crypto);
		val cipherSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
		cipherSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		cSpinner.setAdapter(cipherSpinAdapter);
		cSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(CIPHERS));
		cSpinner.setEnabled(false);

		val hSpinner = (Spinner)findViewById(R.id.spin_hash);
		val hashSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
		hashSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		hSpinner.setAdapter(hashSpinAdapter);
		hSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(HASHES));
		hSpinner.setEnabled(false);

		val mSpinner = (Spinner)findViewById(R.id.spin_mode);
		val modeSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
		modeSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		mSpinner.setAdapter(modeSpinAdapter);
		mSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(MODES));
		mSpinner.setEnabled(false);

		val aSpinner = (Spinner)findViewById(R.id.spin_mac);
		val macSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
		macSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		aSpinner.setAdapter(macSpinAdapter);
		aSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(MACS));
		aSpinner.setEnabled(false);

		// populate algorithm spinners
		cipherSpinAdapter.add(getString(R.string.choose_cipher));
		int i = 1;
		for (val s : CIPHERS)
		{
			cipherSpinAdapter.add(s);
			if (s.equals(cipher))
				cSpinner.setSelection(i);
			i++;
		}

		hashSpinAdapter.add(getString(R.string.choose_hash));
		i = 1;
		for (val s : HASHES)
		{
			hashSpinAdapter.add(s);
			if (s.equals(hash))
				hSpinner.setSelection(i);
			i++;
		}

		modeSpinAdapter.add(getString(R.string.choose_mode));
		i = 1;
		for (val s : MODES)
		{
			modeSpinAdapter.add(s);
			if (s.equals(mode))
				mSpinner.setSelection(i);
			i++;
		}

		macSpinAdapter.add(getString(R.string.choose_mac));
		i = 1;
		for (val s : MACS)
		{
			macSpinAdapter.add(s);
			if (s.equals(mac))
				aSpinner.setSelection(i);
			i++;
		}

		val kdf = (NumberPicker)findViewById(R.id.spin_kdf);
		kdf.setMaxValue(Integer.MAX_VALUE);
		kdf.setMinValue(1);
		kdf.setValue(kdfIterations);
		kdf.setEnabled(false);
		kdf.setOnValueChangedListener((numberPicker, oldValue, newValue) ->
		{
			if (newValue > 0)
				kdfIterations = newValue;
			storePreferences();
		});

		// get reference to password text box
		val pEntry = (EditText)findViewById(R.id.text_password);
		pEntry.addTextChangedListener(new TextWatcher()
		{
			@Override
			public void afterTextChanged(final Editable s)
			{
				password = ((EditText)findViewById(R.id.text_password)).getText().toString();
				if (password.isEmpty())
				{
					password = null;
					checkEnableButtons();
				}
				else
					findViewById(R.id.button_go).setEnabled(true);
			}

			@Override
			public void beforeTextChanged(final CharSequence s, final int start, final int count, final int after)
			{
				/* do nothing */
			}

			@Override
			public void onTextChanged(final CharSequence s, final int start, final int before, final int count)
			{
				/* do nothing */
			}
		});
		pEntry.setEnabled(false);

		// select key file button
		val keyButton = findViewById(R.id.button_key);
		keyButton.setOnClickListener(new FileChooserListener(FileAction.KEY));
		keyButton.setEnabled(false);

		// get reference to encrypt/decrypt button
		val encButton = findViewById(R.id.button_go);
		encButton.setOnClickListener(v ->
		{
			createDoubleProgressDialog();
			startService(createBackgroundTask());
		});
		encButton.setEnabled(false);

		fChooser.requestFocus();

		compress = settings.getBoolean(Options.COMPRESS.toString(), true);
		follow = settings.getBoolean(Options.FOLLOW.toString(), false);
		key_file = settings.getBoolean(Options.KEY.toString(), false);
		raw = settings.getBoolean(Options.RAW.toString(), false);
		version = Version.parseMagicNumber(settings.getLong(Options.VERSION.toString(), Version.CURRENT.magicNumber), Version.CURRENT);
		toggleKeySource();
	}

	@Override
	public void onRequestPermissionsResult(final int requestCode, final String[] permissions, final int[] grantResults)
	{
		if (requestCode == STORAGE_PERMISSION_REQUEST)
			if (!(grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED))
				finishAffinity();
	}

	@Override
	protected void onStop()
	{
		storePreferences();
		((NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE)).cancelAll();
		super.onStop();
	}

	private void checkPermissions()
	{
		for (val permission : STORAGE_PERMISSIONS)
			if (checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED)
			{
				ActivityCompat.requestPermissions(this, STORAGE_PERMISSIONS, STORAGE_PERMISSION_REQUEST);
				return;
			}
	}

	private void storePreferences()
	{
		val editor = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), Context.MODE_PRIVATE).edit();
		editor.putString(Options.CIPHER.toString(), cipher);
		editor.putString(Options.HASH.toString(), hash);
		editor.putString(Options.MODE.toString(), mode);
		editor.putString(Options.MAC.toString(), mac);
		editor.putInt(Options.KDF_ITERATIONS.toString(), kdfIterations);
		editor.putBoolean(Options.COMPRESS.toString(), compress);
		editor.putBoolean(Options.FOLLOW.toString(), follow);
		editor.putBoolean(Options.KEY.toString(), key_file);
		editor.putBoolean(Options.RAW.toString(), raw);
		editor.putLong(Options.VERSION.toString(), version.magicNumber);
		editor.apply();
	}

	@Override
	public boolean onCreateOptionsMenu(final Menu menu)
	{
		getMenuInflater().inflate(R.menu.menu, menu);
		menu.findItem(R.id.menu_options_compress).setChecked(compress);
		menu.findItem(R.id.menu_options_follow).setChecked(follow);
		menu.findItem(R.id.menu_options_key_file).setChecked(key_file);

		// populate version compatibility menu (floating context menu)
		// we cannot have submenu of submenus :( have to rethink this
		val compatibilityMenu = menu.findItem(R.id.menu_advanced_compatibility).getSubMenu();
		int o = Version.values().length;
		for (val v : Version.values())
		{
			if (v == Version.CURRENT) /* no need to duplicate the "current" */
				continue;
			compatibilityMenu.add(R.id.menu_group_compatibility, v.menu_id, o, v.display).setChecked(version.magicNumber == v.magicNumber);
			o--;
		}
		compatibilityMenu.setGroupCheckable(R.id.menu_group_compatibility, true, true);

		return true;
	}

	@SuppressLint("NonConstantResourceId")
	@Override
	public boolean onOptionsItemSelected(final MenuItem menuItem)
	{
		val itemId = menuItem.getItemId();
		if (itemId == R.id.menu_about)
		{
			aboutDialog();
		}
		else if (itemId == R.id.menu_options)
		{
			// do nothing; displays sub-menu
		}
		else if (itemId == R.id.menu_options_compress)
		{
			compress = !menuItem.isChecked();
			menuItem.setChecked(compress);
			Toast.makeText(getApplicationContext(), getString(R.string.compress) + ": " + (compress ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
			storePreferences();
		}
		else if (itemId == R.id.menu_options_follow)
		{
			follow = !menuItem.isChecked();
			menuItem.setChecked(follow);
			Toast.makeText(getApplicationContext(), getString(R.string.follow) + ": " + (follow ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
			storePreferences();
		}
		else if (itemId == R.id.menu_options_key_file)
		{
			key_file = !menuItem.isChecked();
			menuItem.setChecked(key_file);
			Toast.makeText(getApplicationContext(), key_file ? getString(R.string.use_key_file) : getString(R.string.use_password), Toast.LENGTH_SHORT).show();
			toggleKeySource();
			storePreferences();
		}
		else if (itemId == R.id.menu_advanced_raw)
		{
			raw = !menuItem.isChecked();
			menuItem.setChecked(raw);
			Toast.makeText(getApplicationContext(), getString(R.string.raw) + ": " + (raw ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
			storePreferences();
		}
		else if (itemId == R.id.menu_advanced_compatibility)
		{
			// do nothing; displays sub-menu
		}
		else
		{
			checkCompatibilityChange(menuItem);
		}
		return true;
	}

	private void toggleKeySource()
	{
		val pass = (EditText)findViewById(R.id.text_password);
		val key = (Button)findViewById(R.id.button_key);
		pass.setVisibility(key_file ? View.GONE : View.VISIBLE);
		key.setVisibility(key_file ? View.VISIBLE : View.GONE);
		pass.setText("");
		key.setText(R.string.choose_key);
		password = null;
		this.key = null;
	}

	private void aboutDialog()
	{
		val dialog = new Dialog(this);
		dialog.setContentView(R.layout.about);
		dialog.setTitle(getString(R.string.about_title));
		dialog.show();
	}

	private void checkCompatibilityChange(final MenuItem menuItem)
	{
		val itemId = menuItem.getItemId();
		for (val v : Version.values())
			if (itemId == v.menu_id)
			{
				version = v;
				Toast.makeText(getApplicationContext(), getString(R.string.compatibility) + ": " + version.display, Toast.LENGTH_SHORT).show();
				menuItem.setChecked(true);
				storePreferences();
			}
	}

	@Override
	public synchronized void onActivityResult(final int requestCode, final int resultCode, final Intent data)
	{
		if (resultCode != Activity.RESULT_OK || data == null)
			return;
		val uris = new ArrayList<Uri>();
		val uri = data.getData();
		String display;
		if (uri != null)
		{
			uris.add(uri);
			val documentFile = DocumentFile.fromSingleUri(this, uri);
			if (documentFile == null || (display = documentFile.getName()) == null)
				display = uri.getLastPathSegment();
		}
		else
		{
			val clipData = data.getClipData();
			for (int i = 0; i < clipData.getItemCount(); i++)
				uris.add(clipData.getItemAt(i).getUri());
			display = getString(R.string.multipleSelected);
		}
		val fileAction = FileAction.fromValue(requestCode);
		if (fileAction != null)
			switch (fileAction)
			{
				case LOAD:
					filenamesIn = uris;
					((Button)findViewById(R.id.button_file)).setText(display);
					break;
				case SAVE:
					filenameOut = uri;
					((Button)findViewById(R.id.button_output)).setText(display);
					break;
				case KEY:
					key = uri;
					((Button)findViewById(R.id.button_key)).setText(display);
					break;
			}
		checkEnableButtons();
	}

	private void checkEnableButtons()
	{
		val cSpinner = (Spinner)findViewById(R.id.spin_crypto);
		val hSpinner = (Spinner)findViewById(R.id.spin_hash);
		val mSpinner = (Spinner)findViewById(R.id.spin_mode);
		val aSpinner = (Spinner)findViewById(R.id.spin_mac);
		val kdfSpinner = (NumberPicker)findViewById(R.id.spin_kdf);
		val password = (EditText)findViewById(R.id.text_password);
		val keyButton = (Button)findViewById(R.id.button_key);
		val encButton = (Button)findViewById(R.id.button_go);

		hSpinner.setEnabled(false);
		cSpinner.setEnabled(false);
		mSpinner.setEnabled(false);
		aSpinner.setEnabled(false);
		kdfSpinner.setEnabled(false);
		password.setEnabled(false);
		keyButton.setEnabled(false);
		encButton.setEnabled(false);

		// update encryption button text
		if (filenamesIn != null && filenamesIn.size() == 1)
			encrypting = !Crypto.fileEncrypted(this, filenamesIn.get(0));
		if (encrypting)
		{
			encButton.setText(R.string.encrypt);
			if (filenamesIn != null && !filenamesIn.isEmpty() && filenameOut != null)
			{
				cSpinner.setEnabled(true);
				hSpinner.setEnabled(true);
				mSpinner.setEnabled(true);
				aSpinner.setEnabled(true);
				kdfSpinner.setEnabled(true);
				if (cipher != null && hash != null && mode != null && mac != null && kdfIterations > 0)
				{
					password.setEnabled(true);
					keyButton.setEnabled(true);
				}
			}
		}
		else
		{
			encButton.setText(R.string.decrypt);
			if (filenamesIn != null && filenamesIn.size() == 1 && filenameOut != null)
			{
				password.setEnabled(true);
				keyButton.setEnabled(true);
			}
		}
		if (this.password != null || key != null)
			encButton.setEnabled(true);
	}

	private void createDoubleProgressDialog()
	{
		cancelDoubleProgressDialog();
		doubleProgressDialog = new DoubleProgressDialog(Main.this);
		doubleProgressDialog.setMessage(getString(R.string.please_wait));
		doubleProgressDialog.setCanceledOnTouchOutside(false);
		doubleProgressDialog.setOnCancelListener(dialog ->
		{
			stopService(new Intent(getBaseContext(), encrypting ? Encrypt.class : Decrypt.class));
			messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.DONE.value, Status.CANCELLED.message));
		});
		doubleProgressDialog.setMax(1);
		doubleProgressDialog.setProgress(0);
		doubleProgressDialog.setSecondaryMax(1);
		doubleProgressDialog.setSecondaryProgress(0);
		doubleProgressDialog.show();
		/* handle broadcasts from the service about progress */
		progressReceiver = new ProgressReceiver();
		val intentFilter = new IntentFilter();
		intentFilter.addAction(getString(encrypting ? R.string.encrypting : R.string.decrypting));
		registerReceiver(progressReceiver, intentFilter);
		messageHandler = new MessageHandler(Main.this, msg -> {
			val progressUpdate = ProgressUpdate.fromValue(msg.what);
			if (progressUpdate != null && doubleProgressDialog != null)
				switch (progressUpdate)
				{
					case DONE:
						cancelDoubleProgressDialog();
						Toast.makeText(getApplicationContext(), (String)msg.obj, Toast.LENGTH_LONG).show();
						break;
					case CURRENT:
						doubleProgressDialog.setMax(msg.arg1);
						doubleProgressDialog.setProgress(msg.arg2);
						break;
					case TOTAL:
						if (msg.arg1 < 0 || msg.arg2 < 0)
							doubleProgressDialog.hideSecondaryProgress();
						else
						{
							doubleProgressDialog.showSecondaryProgress();
							doubleProgressDialog.setSecondaryMax(msg.arg1);
							doubleProgressDialog.setSecondaryProgress(msg.arg2);
							val currentFile = (String)msg.obj;
							if (currentFile != null)
								doubleProgressDialog.setMessage(currentFile);
						}
						break;
				}
			return true;
		});
	}

	private void cancelDoubleProgressDialog()
	{
		if (doubleProgressDialog != null)
		{
			doubleProgressDialog.dismiss();
			doubleProgressDialog = null;
		}
		if (progressReceiver != null)
		{
			unregisterReceiver(progressReceiver);
			progressReceiver = null;
		}
	}

	private Intent createBackgroundTask()
	{
		/* kick off the actual cipher process */
		val intent = new Intent(getBaseContext(), encrypting ? Encrypt.class : Decrypt.class);

		intent.putExtra(CLASS.toString(), Main.class);
		intent.putExtra(ACTION.toString(), encrypting ? R.string.encrypting : R.string.decrypting);
		intent.putExtra(WAIT.toString(), R.string.please_wait);
		intent.putExtra(ICON.toString(), R.drawable.icon_bw);
		intent.putParcelableArrayListExtra(SOURCE.toString(), filenamesIn);
		intent.putExtra(OUTPUT.toString(), filenameOut);
		intent.putExtra(CIPHER.toString(), cipher);
		intent.putExtra(HASH.toString(), hash);
		intent.putExtra(MODE.toString(), mode);
		intent.putExtra(MAC.toString(), mac);
		intent.putExtra(KDF_ITERATIONS.toString(), kdfIterations);
		intent.putExtra(KEY_FILE.toString(), key_file);
		if (key_file)
			intent.putExtra(KEY.toString(), key);
		else
			intent.putExtra(KEY.toString(), password.getBytes());
		intent.putExtra(RAW.toString(), raw);
		intent.putExtra(COMPRESS.toString(), compress);
		intent.putExtra(FOLLOW.toString(), follow);
		intent.putExtra(VERSION.toString(), version.magicNumber);
		return intent;
	}

	/*
	 * private on... (something) event handlers
	 */

	@RequiredArgsConstructor
	private class FileChooserListener implements OnClickListener
	{
		private final FileAction fileAction;

		@Override
		public void onClick(final View v)
		{
			final Intent intent;
			if (fileAction == FileAction.SAVE && !encrypting)
				intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
			else
			{
				if (fileAction == FileAction.SAVE)
					intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
				else if (fileAction == FileAction.KEY)
					intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
				else
				{
					intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
					intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
				}
				intent.addCategory(Intent.CATEGORY_OPENABLE);
				intent.setType("*/*");
			}
			Main.this.startActivityForResult(intent, fileAction.value);
		}
	}

	@RequiredArgsConstructor
	private class SpinnerSelectedListener implements OnItemSelectedListener
	{
		private final Set<String> choices;

		@Override
		public void onItemSelected(final AdapterView<?> parent, final View view, final int position, final long id)
		{
			String selected = null;
			int i = 0;
			for (var iterator = choices.iterator(); iterator.hasNext(); iterator.next(), i++)
				if (position > 0 && i == position - 1)
				{
					selected = iterator.next();
					break;
				}
			/* yes we are in fact comparing object references */
			if (choices == CIPHERS)
				cipher = selected;
			else if (choices == HASHES)
				hash = selected;
			else if (choices == MODES)
				mode = selected;
			else if (choices == MACS)
				mac = selected;
			if (selected != null)
				storePreferences();
			checkEnableButtons();
		}

		@Override
		public void onNothingSelected(final AdapterView<?> parent)
		{
			/* do nothing */
		}
	}

	/*
	 * notification and progress update handling
	 */

	private class ProgressReceiver extends BroadcastReceiver
	{
		@Override
		public void onReceive(final Context ctx, final Intent intent)
		{
			val currentFile = intent.getStringExtra(CURRENT_FILE.toString());
			val currentOffset = intent.getLongExtra(CURRENT_OFFSET.toString(), 0L);
			val currentSize = intent.getLongExtra(CURRENT_SIZE.toString(), 0L);
			val totalOffset = intent.getLongExtra(TOTAL_OFFSET.toString(), 0L);
			val totalSize = intent.getLongExtra(TOTAL_SIZE.toString(), 0L);
			val status = Status.parseStatus(intent.getStringExtra(STATUS.toString()));

			if (status == Status.INIT || status == Status.RUNNING)
			{
				messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.CURRENT.value, (int)currentSize, (int)currentOffset));
				if (totalSize != currentSize && totalSize > 1)
					messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.TOTAL.value, (int)totalSize, (int)totalOffset, currentFile));
				else
					messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.TOTAL.value, -1, -1));
			}
			else if (status != null)
				messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.DONE.value, status.message));
		}
	}

	private static class MessageHandler extends Handler
	{
		private final WeakReference<Activity> reference;
		private final Callback callback;

		public MessageHandler(final Activity service, final Callback callback)
		{
			super(Looper.myLooper(), callback);
			reference = new WeakReference<>(service);
			this.callback = callback;
		}

		@Override
		public void handleMessage(final Message msg)
		{
			val service = reference.get();
			if (service != null)
				callback.handleMessage(msg);
		}
	}
}
