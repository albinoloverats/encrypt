/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2015, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.free;

import android.app.Activity;
import android.app.Dialog;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.preference.PreferenceManager;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.SubMenu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdView;
import com.lamerman.FileDialog;
import com.simaomata.DoubleProgressDialog;

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
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

public class MainFree extends Activity
{
	private static Context context; /* used for Status messages */

	private static final Set<String> CIPHERS = CryptoUtils.getCipherAlgorithmNames();
	private static final Set<String> HASHES = CryptoUtils.getHashAlgorithmNames();
	private static final Set<String> MODES = CryptoUtils.getCipherModeNames();

	private DoubleProgressDialog doubleProgressDialog;
	private ProgressReceiver progressReceiver;
	private MessageHandler messageHandler;

	private boolean compress = true;
	private boolean follow = false;
	private boolean key_file = false;
	private boolean raw = false;
	private Version version = Version.CURRENT;

	private String filenameIn;
	private String filenameOut;
	private boolean encrypting = true;
	private String cipher;
	private String hash;
	private String mode;
	private String password;
	private String key;

	@Override
	public void onCreate(final Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		context = this;

		final SharedPreferences settings = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), Context.MODE_PRIVATE);
		cipher = settings.getString(Options.CIPHER.toString(), null);
		hash = settings.getString(Options.HASH.toString(), null);
		mode = settings.getString(Options.MODE.toString(), null);

		// setup the file chooser button
		final Button fChooser = (Button)findViewById(R.id.button_file);
		fChooser.setOnClickListener(new FileChooserListener(FileAction.LOAD));

		// setup the file output chooser button
		findViewById(R.id.button_output).setOnClickListener(new FileChooserListener(FileAction.SAVE));

		// setup the hash and crypto spinners
		final Spinner cSpinner = (Spinner)findViewById(R.id.spin_crypto);
		final ArrayAdapter<CharSequence> cipherSpinAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item);
		cipherSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		cSpinner.setAdapter(cipherSpinAdapter);
		cSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(CIPHERS));
		cSpinner.setEnabled(false);

		final Spinner hSpinner = (Spinner)findViewById(R.id.spin_hash);
		final ArrayAdapter<CharSequence> hashSpinAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item);
		hashSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		hSpinner.setAdapter(hashSpinAdapter);
		hSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(HASHES));
		hSpinner.setEnabled(false);

		final Spinner mSpinner = (Spinner)findViewById(R.id.spin_mode);
		final ArrayAdapter<CharSequence> modeSpinAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item);
		modeSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		mSpinner.setAdapter(modeSpinAdapter);
		mSpinner.setOnItemSelectedListener(new SpinnerSelectedListener(MODES));
		mSpinner.setEnabled(false);

		// populate algorithm spinners
		cipherSpinAdapter.add(getString(R.string.choose_cipher));
		int i = 1;
		for (final String s : CIPHERS)
		{
			cipherSpinAdapter.add(s);
			if (s.equals(cipher))
				cSpinner.setSelection(i);
			i++;
		}

		hashSpinAdapter.add(getString(R.string.choose_hash));
		i = 1;
		for (final String s : HASHES)
		{
			hashSpinAdapter.add(s);
			if (s.equals(hash))
				hSpinner.setSelection(i);
			i++;
		}

		modeSpinAdapter.add(getString(R.string.choose_mode));
		i = 1;
		for (final String s : MODES)
		{
			modeSpinAdapter.add(s);
			if (s.equals(mode))
				mSpinner.setSelection(i);
			i++;
		}

		// get reference to password text box
		final EditText pEntry = (EditText)findViewById(R.id.text_password);
		pEntry.addTextChangedListener(new TextWatcher()
		{
			@Override
			public void afterTextChanged(final Editable s)
			{
				password = ((EditText)findViewById(R.id.text_password)).getText().toString();
				if (password == null || password.length() == 0)
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
				;
			}

			@Override
			public void onTextChanged(final CharSequence s, final int start, final int before, final int count)
			{
				;
			}
		});
		pEntry.setEnabled(false);

		// select key file button
		final Button keyButton = (Button)findViewById(R.id.button_key);
		keyButton.setOnClickListener(new FileChooserListener(FileAction.KEY));
		keyButton.setEnabled(false);

		// get reference to encrypt/decrypt button
		final Button encButton = (Button)findViewById(R.id.button_go);
		encButton.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(final View v)
			{
				createDoubleProgressDialog();
				startService(createBackgroundTask());
			}
		});
		encButton.setEnabled(false);

		fChooser.requestFocus();

		compress = settings.getBoolean(Options.COMPRESS.toString(), true);
		follow = settings.getBoolean(Options.FOLLOW.toString(), false);
		key_file = settings.getBoolean(Options.KEY.toString(), false);
		raw = settings.getBoolean(Options.RAW.toString(), false);
		version = Version.parseMagicNumber(settings.getLong(Options.VERSION.toString(), Version.CURRENT.magicNumber), Version.CURRENT);
		toggleKeySource();

		final AdRequest.Builder adRequestBuilder = new AdRequest.Builder();
		if (BuildConfig.DEBUG)
		{
			adRequestBuilder.addTestDevice(AdRequest.DEVICE_ID_EMULATOR);
			adRequestBuilder.addTestDevice("463890CB55C5B59AE12223411206E40A");
			((AdView)findViewById(R.id.ad_banner_test)).loadAd(adRequestBuilder.build());
		}
		else
			((AdView)findViewById(R.id.ad_banner_live)).loadAd(adRequestBuilder.build());
	}

	@Override
	protected void onStop()
	{
		storePreferences();
		((NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE)).cancelAll();
		super.onStop();
	}

	public static Context getContext()
	{
		return context;
	}

	private void storePreferences()
	{
		final SharedPreferences.Editor editor = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), Context.MODE_PRIVATE).edit();
		editor.putString(Options.CIPHER.toString(), cipher);
		editor.putString(Options.HASH.toString(), hash);
		editor.putString(Options.MODE.toString(), mode);
		editor.putBoolean(Options.COMPRESS.toString(), compress);
		editor.putBoolean(Options.FOLLOW.toString(), follow);
		editor.putBoolean(Options.KEY.toString(), key_file);
		editor.putBoolean(Options.RAW.toString(), raw);
		editor.putLong(Options.VERSION.toString(), version.magicNumber);
		editor.commit();
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
		final SubMenu compatibilityMenu = menu.findItem(R.id.menu_advanced_compatibility).getSubMenu();
		int o = Version.values().length;
		for (final Version v : Version.values())
		{
			if (v == Version.CURRENT) /* no need to duplicate the "current" */
				continue;
			compatibilityMenu.add(R.id.menu_group_compatibility, v.menu_id, o, v.display).setChecked(version.magicNumber == v.magicNumber);
			o--;
		}
		compatibilityMenu.setGroupCheckable(R.id.menu_group_compatibility, true, true);

		return true;
	}

	@Override
	public boolean onOptionsItemSelected(final MenuItem menuItem)
	{
		switch (menuItem.getItemId())
		{
			case R.id.menu_about:
				aboutDialog();
				break;
			case R.id.menu_options:
				break;
			case R.id.menu_options_compress:
				compress = !menuItem.isChecked();
				menuItem.setChecked(compress);
				Toast.makeText(getApplicationContext(), getString(R.string.compress) + ": " + (compress ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
				storePreferences();
				break;
			case R.id.menu_options_follow:
				follow = !menuItem.isChecked();
				menuItem.setChecked(follow);
				Toast.makeText(getApplicationContext(), getString(R.string.follow) + ": " + (follow ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
				storePreferences();
				break;
			case R.id.menu_options_key_file:
				key_file = !menuItem.isChecked();
				menuItem.setChecked(key_file);
				Toast.makeText(getApplicationContext(), key_file ? getString(R.string.use_key_file) : getString(R.string.use_password), Toast.LENGTH_SHORT).show();
				toggleKeySource();
				storePreferences();
				break;
			case R.id.menu_advanced_raw:
				raw = !menuItem.isChecked();
				menuItem.setChecked(raw);
				Toast.makeText(getApplicationContext(), getString(R.string.raw) + ": " + (raw ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
				storePreferences();
				break;
			case R.id.menu_advanced_compatibility:
				break;
			case R.id.menu_remove_ads:
				final Intent i = new Intent(Intent.ACTION_VIEW);
				i.setData(Uri.parse("market://details?id=net.albinoloverats.android.encrypt"));
				startActivity(i);
				break;
			default:
				checkCompatibilityChange(menuItem);
				break;
		}
		return true;
	}

	private void toggleKeySource()
	{
		final EditText pass = (EditText)findViewById(R.id.text_password);
		final Button key = (Button)findViewById(R.id.button_key);
		pass.setVisibility(key_file ? View.GONE : View.VISIBLE);
		key.setVisibility(key_file ? View.VISIBLE : View.GONE);
	}

	/*
	 * show about dialog
	 */
	private void aboutDialog()
	{
		final Dialog dialog = new Dialog(this);
		dialog.setContentView(R.layout.about);
		dialog.setTitle(getString(R.string.app_name) + " " + getString(R.string.version));
		((ImageView)dialog.findViewById(R.id.about_image)).setImageResource(R.drawable.about);
		((TextView)dialog.findViewById(R.id.about_text)).setText(getString(R.string.description) + "\n" + getString(R.string.copyright) + "\n" + getString(R.string.url));
		dialog.show();
	}

	private void checkCompatibilityChange(final MenuItem menuItem)
	{
		final int itemId = menuItem.getItemId();
		for (final Version v : Version.values())
		{
			if (itemId == v.menu_id)
			{
				version = v;
				Toast.makeText(getApplicationContext(), getString(R.string.compatibility) + ": " + version.display, Toast.LENGTH_SHORT).show();
				menuItem.setChecked(true);
				storePreferences();
			}
		}
	}

	@Override
	public synchronized void onActivityResult(final int requestCode, final int resultCode, final Intent data)
	{
		if (resultCode != Activity.RESULT_OK)
			return;

		final String filename = data.getStringExtra(FileDialog.RESULT_PATH);
		final FileAction fileAction = FileAction.fromValue(requestCode);
		if (fileAction != null)
			switch (fileAction)
			{
				case LOAD:
					filenameIn = filename;
					((Button)findViewById(R.id.button_file)).setText(filenameIn);
					break;
				case SAVE:
					filenameOut = filename;
					((Button)findViewById(R.id.button_output)).setText(filenameOut);
					break;
				case KEY:
					((Button)findViewById(R.id.button_key)).setText(filename);
					key = filename;
					break;
			}
		checkEnableButtons();
	}

	private void checkEnableButtons()
	{
		final Spinner cSpinner  = (Spinner)findViewById(R.id.spin_crypto);
		final Spinner hSpinner  = (Spinner)findViewById(R.id.spin_hash);
		final Spinner mSpinner  = (Spinner)findViewById(R.id.spin_mode);
		final EditText password = (EditText)findViewById(R.id.text_password);
		final Button keyButton  = (Button)findViewById(R.id.button_key);
		final Button encButton  = (Button)findViewById(R.id.button_go);

		hSpinner.setEnabled(false);
		cSpinner.setEnabled(false);
		mSpinner.setEnabled(false);
		password.setEnabled(false);
		keyButton.setEnabled(false);
		encButton.setEnabled(false);

		// update encryption button text
		if (filenameIn != null)
			encrypting = !Crypto.fileEncrypted(filenameIn);
		if (encrypting)
		{
			encButton.setText(R.string.encrypt);
			if (filenameIn != null && filenameOut != null)
			{
				cSpinner.setEnabled(true);
				hSpinner.setEnabled(true);
				mSpinner.setEnabled(true);
				if (cipher != null && hash != null && mode != null)
				{
					password.setEnabled(true);
					keyButton.setEnabled(true);
				}
			}
		}
		else
		{
			encButton.setText(R.string.decrypt);
			if (filenameIn != null && filenameOut != null)
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
		doubleProgressDialog = new DoubleProgressDialog(MainFree.this);
		doubleProgressDialog.setMessage(getString(R.string.please_wait));
		doubleProgressDialog.setOnCancelListener(new OnCancelListener()
		{
			@Override
			public void onCancel(final DialogInterface dialog)
			{
				stopService(new Intent(getBaseContext(), encrypting ? Encrypt.class : Decrypt.class));
				messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.DONE.value, Status.CANCELLED.message));
			}
		});
		doubleProgressDialog.setMax(1);
		doubleProgressDialog.setProgress(0);
		doubleProgressDialog.setSecondaryMax(1);
		doubleProgressDialog.setSecondaryProgress(0);
		/* handle broadcasts from the service about progress */
		progressReceiver = new ProgressReceiver();
		final IntentFilter intentFilter = new IntentFilter();
		intentFilter.addAction(getString(encrypting ? R.string.encrypting : R.string.decrypting));
		registerReceiver(progressReceiver, intentFilter);
		messageHandler = new MessageHandler(MainFree.this);
		doubleProgressDialog.show();
	}

	private Intent createBackgroundTask()
	{
		/* kick off the actually cipher process */
		Intent intent = null;
		if (encrypting)
			intent = new Intent(getBaseContext(), Encrypt.class);
		else
			intent = new Intent(getBaseContext(), Decrypt.class);

		intent.putExtra("class", MainFree.class);
		intent.putExtra("action", encrypting ? R.string.encrypting : R.string.decrypting);
		intent.putExtra("wait", R.string.please_wait);
		intent.putExtra("icon", R.drawable.icon_bw);

		intent.putExtra("source", filenameIn);
		intent.putExtra("output", filenameOut);
		intent.putExtra("cipher", cipher);
		intent.putExtra("hash", hash);
		intent.putExtra("mode", mode);
		intent.putExtra("key_file", key_file);
		if (key_file)
			intent.putExtra("key", key);
		else
			intent.putExtra("key", password.getBytes());
		intent.putExtra("raw", raw);
		intent.putExtra("compress", compress);
		intent.putExtra("follow", follow);
		intent.putExtra("version", version.magicNumber);
		return intent;
	}

	/*
	 * private on... (something) classes
	 */

	private class FileChooserListener implements OnClickListener
	{
		private final FileAction fileAction;

		public FileChooserListener(final FileAction fileAction)
		{
			this.fileAction = fileAction;
		}

		@Override
		public void onClick(final View v)
		{
			final Intent intent = new Intent(context, FileDialog.class);
			intent.putExtra(FileDialog.START_PATH, Environment.getExternalStorageDirectory().getPath());
			intent.putExtra(FileDialog.CAN_SELECT_DIR, fileAction != FileAction.KEY);
			MainFree.this.startActivityForResult(intent, fileAction.value);
		}
	}

	private class SpinnerSelectedListener implements OnItemSelectedListener
	{
		private final Set<String> choices;

		public SpinnerSelectedListener(final Set<String> choices)
		{
			this.choices = choices;
		}

		@Override
		public void onItemSelected(final AdapterView<?> parent, final View view, final int position, final long id)
		{
			String selected = null;
			int i = 0;
			for (final Iterator<String> iterator = choices.iterator(); iterator.hasNext(); iterator.next(), i++)
				if (position > 0 && i == position - 1)
				{
					selected = iterator.next();
					break;
				}
			if (choices == CIPHERS)
				cipher = selected;
			else if (choices == HASHES)
				hash = selected;
			else if (choices == MODES)
				mode = selected;
			if (selected != null)
				storePreferences();
			checkEnableButtons();
		}

		@Override
		public void onNothingSelected(final AdapterView<?> parent)
		{
			;
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
			final long currentOffset = intent.getLongExtra("current.offset", 0L);
			final long currentSize   = intent.getLongExtra("current.size", 0L);
			final long totalOffset   = intent.getLongExtra("total.offset", 0L);
			final long totalSize     = intent.getLongExtra("total.size", 0L);
			final Status status      = Status.parseStatus(intent.getStringExtra("status"));

			if (status == Status.INIT || status == Status.RUNNING)
			{
				messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.CURRENT.value, (int)currentSize, (int)currentOffset));
				if (totalSize != currentSize && totalSize > 1)
					messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.TOTAL.value, (int)totalSize, (int)totalOffset));
				else
					messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.TOTAL.value, -1, -1));
			}
			else if (status != null)
				messageHandler.sendMessage(messageHandler.obtainMessage(ProgressUpdate.DONE.value, status.message));
		}
	}

	private static class MessageHandler extends Handler
	{
		private WeakReference<MainFree> reference;

		public MessageHandler(final MainFree service)
		{
			reference = new WeakReference<>(service);
		}

		@Override
		public void handleMessage(final Message msg)
		{
			final MainFree service = reference.get();
			if (service != null)
				service.handleMessage(msg);
		}
	}

	private void handleMessage(final Message msg)
	{
		final ProgressUpdate progressUpdate = ProgressUpdate.fromValue(msg.what);
		if (progressUpdate != null)
			switch (progressUpdate)
			{
				case DONE:
					doubleProgressDialog.dismiss();
					Toast.makeText(getApplicationContext(), (String)msg.obj, Toast.LENGTH_LONG).show();
					unregisterReceiver(progressReceiver);
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
					}
					break;
			}
	}
}
