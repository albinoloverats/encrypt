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

package net.albinoloverats.android.encrypt;

import java.io.File;
import java.lang.ref.WeakReference;
import java.util.Iterator;
import java.util.Set;

import net.albinoloverats.android.encrypt.crypt.Crypto;
import net.albinoloverats.android.encrypt.crypt.CryptoProcessException;
import net.albinoloverats.android.encrypt.crypt.CryptoUtils;
import net.albinoloverats.android.encrypt.crypt.Decrypt;
import net.albinoloverats.android.encrypt.crypt.Encrypt;
import net.albinoloverats.android.encrypt.crypt.Status;
import net.albinoloverats.android.encrypt.crypt.Version;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
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

import com.lamerman.FileDialog;
import com.simaomata.DoubleProgressDialog;

public class Main extends Activity
{
    private static final int DOUBLE_PROGRESS_DIALOG = 1;

    private static Context context;

    private Set<String> cipherNames;
    private Set<String> hashNames;
    private Set<String> modeNames;

    private DoubleProgressDialog dProgressDialog;
    private ProgressThread progressThread;

    private boolean compress = true;
    private boolean follow = false;
    private boolean key_file = false;
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

        final SharedPreferences settings = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), 0);
        cipher = settings.getString(Options.CIPHER.toString(), null);
        hash = settings.getString(Options.HASH.toString(), null);
        mode = settings.getString(Options.MODE.toString(), null);

        // setup the file chooser button
        final Button fChooser = (Button)findViewById(R.id.button_file);
        fChooser.setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(final View v)
            {
                final Intent intent = new Intent(Main.this.getBaseContext(), FileDialog.class);
                intent.putExtra(FileDialog.START_PATH, Environment.getExternalStorageDirectory().getPath());
                intent.putExtra(FileDialog.CAN_SELECT_DIR, true);
                Main.this.startActivityForResult(intent, FileAction.LOAD.value);
            }
        });

        // setup the file output chooser button
        final Button oChooser = (Button)findViewById(R.id.button_output);
        oChooser.setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(final View v)
            {
                final Intent intent = new Intent(Main.this.getBaseContext(), FileDialog.class);
                intent.putExtra(FileDialog.START_PATH, Environment.getExternalStorageDirectory().getPath());
                intent.putExtra(FileDialog.CAN_SELECT_DIR, true);
                Main.this.startActivityForResult(intent, FileAction.SAVE.value);
            }
        });

        // setup the hash and crypto spinners
        final Spinner cSpinner = (Spinner)findViewById(R.id.spin_crypto);
        final ArrayAdapter<CharSequence> cipherSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
        cipherSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        cSpinner.setAdapter(cipherSpinAdapter);
        cSpinner.setOnItemSelectedListener(new OnItemSelectedListener()
        {
            @Override
            public void onItemSelected(final AdapterView<?> parent, final View view, final int position, final long id)
            {
                int i = 0;
                for (final Iterator<String> iterator = cipherNames.iterator(); iterator.hasNext(); i++)
                    if (position > 0 && i == position - 1)
                    {
                        cipher = iterator.next();
                        storePreferences();
                    }
                    else
                    {
                        if (position == 0)
                            cipher = null;
                        iterator.next();
                    }
                checkEnableButtons();
            }

            @Override
            public void onNothingSelected(final AdapterView<?> parent)
            {
                ;
            }
        });
        cSpinner.setEnabled(false);

        final Spinner hSpinner = (Spinner)findViewById(R.id.spin_hash);
        final ArrayAdapter<CharSequence> hashSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
        hashSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        hSpinner.setAdapter(hashSpinAdapter);
        hSpinner.setOnItemSelectedListener(new OnItemSelectedListener()
        {
            @Override
            public void onItemSelected(final AdapterView<?> parent, final View view, final int position, final long id)
            {
                int i = 0;
                for (final Iterator<String> iterator = hashNames.iterator(); iterator.hasNext(); i++)
                    if (i > 0 && i == position - 1)
                    {
                        hash = iterator.next();
                        storePreferences();
                    }
                    else
                    {
                        if (position == 0)
                            hash = null;
                        iterator.next();
                    }
                checkEnableButtons();
            }

            @Override
            public void onNothingSelected(final AdapterView<?> parent)
            {
                ;
            }
        });
        hSpinner.setEnabled(false);

        final Spinner mSpinner = (Spinner)findViewById(R.id.spin_mode);
        final ArrayAdapter<CharSequence> modeSpinAdapter = new ArrayAdapter<CharSequence>(this, android.R.layout.simple_spinner_item);
        modeSpinAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mSpinner.setAdapter(modeSpinAdapter);
        mSpinner.setOnItemSelectedListener(new OnItemSelectedListener()
        {
            @Override
            public void onItemSelected(final AdapterView<?> parent, final View view, final int position, final long id)
            {
                int i = 0;
                for (final Iterator<String> iterator = modeNames.iterator(); iterator.hasNext(); i++)
                    if (position > 0 && i == position - 1)
                    {
                        mode = iterator.next();
                        storePreferences();
                    }
                    else
                    {
                        if (position == 0)
                            mode = null;
                        iterator.next();
                    }
                checkEnableButtons();
            }

            @Override
            public void onNothingSelected(final AdapterView<?> parent)
            {
                ;
            }
        });
        mSpinner.setEnabled(false);

        // populate algorithm spinners
        cipherNames = CryptoUtils.getCipherAlgorithmNames();
        hashNames = CryptoUtils.getHashAlgorithmNames();
        modeNames = CryptoUtils.getCipherModeNames();
        cipherSpinAdapter.add(getString(R.string.choose_cipher));
        int i = 1;
        for (final String s : cipherNames)
        {
            cipherSpinAdapter.add(s);
            if (s.equals(cipher))
                cSpinner.setSelection(i);
            i++;
        }
        hashSpinAdapter.add(getString(R.string.choose_hash));
        i = 1;
        for (final String s : hashNames)
        {
            hashSpinAdapter.add(s);
            if (s.equals(hash))
                hSpinner.setSelection(i);
            i++;
        }
        modeSpinAdapter.add(getString(R.string.choose_mode));
        i = 1;
        for (final String s : modeNames)
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
                    ((Button)findViewById(R.id.button_go)).setEnabled(true);
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
        keyButton.setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(final View v)
            {
                final Intent intent = new Intent(Main.this.getBaseContext(), FileDialog.class);
                intent.putExtra(FileDialog.START_PATH, Environment.getExternalStorageDirectory().getPath());
                intent.putExtra(FileDialog.CAN_SELECT_DIR, false);
                Main.this.startActivityForResult(intent, FileAction.KEY.value);
            }
        });
        keyButton.setEnabled(false);

        // get reference to encrypt/decrypt button
        final Button encButton = (Button)findViewById(R.id.button_go);
        encButton.setOnClickListener(new OnClickListener()
        {
            @Override
            public void onClick(final View v)
            {
                showDialog(DOUBLE_PROGRESS_DIALOG);
            }
        });
        encButton.setEnabled(false);

        fChooser.requestFocus();

        compress = settings.getBoolean(Options.COMPRESS.toString(), true);
        follow = settings.getBoolean(Options.FOLLOW.toString(), false);
        key_file = settings.getBoolean(Options.KEY.toString(), false);
        try
        {
            version = Version.parseMagicNumber(settings.getLong(Options.VERSION.toString(), Version.CURRENT.magicNumber));
        }
        catch (final CryptoProcessException e)
        {
            version = Version.CURRENT;
        }
        toggleKeySource();
    }

    @Override
    protected void onStop()
    {
        super.onStop();
        storePreferences();
    }

    private void storePreferences()
    {
        final SharedPreferences.Editor editor = getSharedPreferences(Options.ENCRYPT_PREFERENCES.toString(), 0).edit();
        editor.putString(Options.CIPHER.toString(), cipher);
        editor.putString(Options.HASH.toString(), hash);
        editor.putString(Options.MODE.toString(), mode);
        editor.putBoolean(Options.COMPRESS.toString(), compress);
        editor.putBoolean(Options.FOLLOW.toString(), follow);
        editor.putBoolean(Options.KEY.toString(), key_file);
        editor.putLong(Options.VERSION.toString(), version.magicNumber);
        editor.commit();
    }

    @Override
    public boolean onCreateOptionsMenu(final Menu menu)
    {
        getMenuInflater().inflate(R.menu.menu, menu);
        menu.findItem(R.id.menu_item_compress).setChecked(compress);
        menu.findItem(R.id.menu_item_follow).setChecked(follow);
        menu.findItem(R.id.menu_item_key_file).setChecked(key_file);

        // populate version compatibility menu
        final SubMenu compatibilityMenu = menu.findItem(R.id.menu_item_compatibility).getSubMenu();
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
    public boolean onOptionsItemSelected(final MenuItem item)
    {
        final int itemId = item.getItemId();
        switch (itemId)
        {
            case R.id.menu_item_about:
                aboutDialog();
                break;
//            case R.id.menu_item_compatibility:
            case R.id.menu_item_options:
                break;
            case R.id.menu_item_compress:
                compress = !item.isChecked();
                item.setChecked(compress);
                Toast.makeText(getApplicationContext(), getString(R.string.compress) + ": " + (compress ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
                storePreferences();
                break;
            case R.id.menu_item_follow:
                follow = !item.isChecked();
                item.setChecked(follow);
                Toast.makeText(getApplicationContext(), getString(R.string.follow) + ": " + (follow ? getString(R.string.on) : getString(R.string.off)), Toast.LENGTH_SHORT).show();
                storePreferences();
                break;
            case R.id.menu_item_key_file:
                key_file = !item.isChecked();
                item.setChecked(key_file);
                Toast.makeText(getApplicationContext(), key_file ? getString(R.string.use_key_file) : getString(R.string.use_password), Toast.LENGTH_SHORT).show();
                toggleKeySource();
                storePreferences();
                break;
            default:
                for (final Version v : Version.values())
                {
                    if (itemId == v.menu_id)
                    {
                        version = v;
                        Toast.makeText(getApplicationContext(), getString(R.string.compatibility) + ": " + version.display, Toast.LENGTH_SHORT).show();
                        item.setChecked(true);
                        storePreferences();
                    }
                }
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
        ((ImageView)dialog.findViewById(R.id.about_image)).setImageResource(R.drawable.icon);
        ((TextView)dialog.findViewById(R.id.about_text)).setText(getString(R.string.shpeel) + "\n" + getString(R.string.copyright) + "\n" + getString(R.string.url));
        dialog.show();
    }

    @Override
    public synchronized void onActivityResult(final int requestCode, final int resultCode, final Intent data)
    {
        if (resultCode == Activity.RESULT_OK)
        {
            final String filename = data.getStringExtra(FileDialog.RESULT_PATH);
            switch (FileAction.fromValue(requestCode))
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
    }

    @Override
    protected Dialog onCreateDialog(final int id)
    {
        switch (id)
        {
            case DOUBLE_PROGRESS_DIALOG:
                dProgressDialog = new DoubleProgressDialog(Main.this);
                dProgressDialog.setMessage(getString(R.string.please_wait));
                dProgressDialog.setOnCancelListener(new OnCancelListener()
                {
                    @Override
                    public void onCancel(final DialogInterface dialog)
                    {
                        progressThread.interrupt();
                    }
                });
                return dProgressDialog;
            default:
                return null;
        }
    }

    @Override
    protected void onPrepareDialog(final int id, final Dialog dialog)
    {
        if (id == DOUBLE_PROGRESS_DIALOG)
        {
            dProgressDialog.setMax(1);
            dProgressDialog.setProgress(0);
            dProgressDialog.setSecondaryMax(1);
            dProgressDialog.setSecondaryProgress(0);
            progressThread = new ProgressThread(new StaticMessageHandler(this));
            progressThread.start();
        }
    }

    public static Context getContext()
    {
        return context;
    }

    private static class StaticMessageHandler extends Handler
    {
        private WeakReference<Main> reference;

        public StaticMessageHandler(final Main service)
        {
            reference = new WeakReference<Main>(service);
        }

        @Override
        public void handleMessage(final Message msg)
        {
             final Main service = reference.get();
             if (service != null)
                  service.handleMessage(msg);
        }
    }

    private void handleMessage(final Message msg)
    {
        switch (ProgressUpdate.fromValue(msg.what))
        {
            case DONE:
                dismissDialog(DOUBLE_PROGRESS_DIALOG);
                Toast.makeText(getApplicationContext(), (String)msg.obj, Toast.LENGTH_LONG).show();
                break;
            case CURRENT:
                dProgressDialog.setMax(msg.arg1);
                dProgressDialog.setProgress(msg.arg2);
                break;
            case TOTAL:
                if (msg.arg1 < 0 || msg.arg2 < 0)
                    dProgressDialog.hideSecondaryProgress();
                else
                {
                    dProgressDialog.showSecondaryProgress();
                    dProgressDialog.setSecondaryMax(msg.arg1);
                    dProgressDialog.setSecondaryProgress(msg.arg2);
                }
                break;
        }
    }

    private void checkEnableButtons()
    {
        final Spinner cSpinner = (Spinner)findViewById(R.id.spin_crypto);
        final Spinner hSpinner = (Spinner)findViewById(R.id.spin_hash);
        final Spinner mSpinner = (Spinner)findViewById(R.id.spin_mode);
        final EditText passwd = (EditText)findViewById(R.id.text_password);
        final Button keyButton = (Button)findViewById(R.id.button_key);
        final Button encButton = (Button)findViewById(R.id.button_go);

        hSpinner.setEnabled(false);
        cSpinner.setEnabled(false);
        mSpinner.setEnabled(false);
        passwd.setEnabled(false);
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
            }
            if (cipher != null && hash != null && mode != null)
            {
                passwd.setEnabled(true);
                keyButton.setEnabled(true);
            }
        }
        else
        {
            encButton.setText(R.string.decrypt);
            if (filenameIn != null && filenameOut != null)
            {
                passwd.setEnabled(true);
                keyButton.setEnabled(true);
            }
        }
        if (password != null || key != null)
            encButton.setEnabled(true);
    }

    private class ProgressThread extends Thread
    {
        private final Handler mHandler;

        private ProgressThread(final Handler h)
        {
            mHandler = h;
        }

        @Override
        public void run()
        {
            Status s = null;
            Crypto c = null;

            final PowerManager powerManager = (PowerManager) getSystemService(POWER_SERVICE);
            final WakeLock wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "encryptLock");
            wakeLock.acquire();

            try
            {
                c = encrypting ? new Encrypt(filenameIn, filenameOut, cipher, hash, mode, compress, follow, version) : new Decrypt(filenameIn, filenameOut);
                c.setKey(key_file ? new File(key) : password.getBytes());
                c.start();

                do
                {
                    sleep(2);
                    if (isInterrupted())
                        c.status = Status.CANCELLED;
                    if (c.status == Status.INIT)
                        continue;

                    mHandler.sendMessage(mHandler.obtainMessage(ProgressUpdate.CURRENT.value, (int)c.current.size, (int)c.current.offset));
                    if (c.total.size != c.current.size && c.total.size > 1)
                        mHandler.sendMessage(mHandler.obtainMessage(ProgressUpdate.TOTAL.value, (int)c.total.size, (int)c.total.offset));
                    else
                        mHandler.sendMessage(mHandler.obtainMessage(ProgressUpdate.TOTAL.value, -1, -1));
                }
                while (c.status == Status.INIT || c.status == Status.RUNNING);
            }
            catch (final InterruptedException e)
            {
                c.status = Status.CANCELLED;
            }
            catch (final CryptoProcessException e)
            {
                s = e.code;
            }
            catch (final Throwable t)
            {
                s = Status.FAILED_OTHER;
                if (c != null)
                    c.status = s;
            }
            finally
            {
                wakeLock.release();
            }

            if (c != null)
                s = c.status;

            mHandler.sendMessage(mHandler.obtainMessage(ProgressUpdate.DONE.value, s.message));
        }
    }
}
