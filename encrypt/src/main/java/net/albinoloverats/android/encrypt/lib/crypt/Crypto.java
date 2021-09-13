/*
 * encrypt ~ a simple, modular, (multi-OS) encryption utility
 * Copyright © 2005-2021, albinoloverats ~ Software Development
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

package net.albinoloverats.android.encrypt.lib.crypt;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import android.os.PowerManager;
import android.renderscript.ScriptGroup;

import net.albinoloverats.android.encrypt.lib.io.HashMAC;
import net.albinoloverats.android.encrypt.lib.misc.Convert;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import androidx.core.app.NotificationCompat;
import androidx.documentfile.provider.DocumentFile;

public abstract class Crypto extends Service implements Runnable
{
	protected static final long[] HEADER = { 0x3697de5d96fca0faL, 0xc845c2fa95e2f52dL, Version.CURRENT.magicNumber };

	protected static final int BLOCK_SIZE = 1024;
	protected static final int KDF_ITERATIONS_201709 = 1024;
	public static final int KDF_ITERATIONS_DEFAULT = 32768;

	protected ContentResolver contentResolver;

	protected InputStream source;
	protected OutputStream output;

	protected Uri path;

	protected String name;
	protected String cipher;
	protected String hash;
	protected String mode;
	protected String mac;
	protected byte[] key;
	protected int kdfIterations;

	protected boolean raw = false;

	public Status status;
	public final Progress current = new Progress();
	public final Progress total = new Progress();

	protected int blockSize;
	protected boolean compressed = false;
	protected boolean directory = false;
	protected boolean follow_links = false;

	protected Version version = Version.CURRENT;

	protected HashMAC verification;

	private Thread process;
	private Thread notification;
	private PowerManager.WakeLock wakeLock;

	private String actionTitle;

	@Override
	public void run()
	{
		try
		{
			process();
		}
		catch (final CryptoProcessException e)
		{
			status = e.code;
		}
		catch (final InterruptedException e)
		{
			status = Status.CANCELLED;
		}
		finally
		{
			releaseWakeLock();
		}
	}

	abstract protected void process() throws InterruptedException, CryptoProcessException;

	@Override
	public int onStartCommand(final Intent intent, final int flags, final int startId)
	{
		status = Status.INIT;

		final Class<?> clas = (Class<?>)intent.getSerializableExtra("class");
		final int action = intent.getIntExtra("action", 0);
		final int wait = intent.getIntExtra("wait", 0);
		final int icon = intent.getIntExtra("icon", 0);

		// FIXME needs context, content resolvers, etc...
		if (intent.getBooleanExtra("key_file", false))
			setKey(intent.getStringExtra("key"));
		else
			key = intent.getByteArrayExtra("key");

		actionTitle = getString(action);

		final NotificationCompat.Builder notificationBuilder = new NotificationCompat.Builder(getBaseContext(), null);
		notificationBuilder.setContentTitle(actionTitle);
		notificationBuilder.setContentText(getString(wait));
		notificationBuilder.setSmallIcon(icon);

		final Intent notificationIntent = new Intent(this, clas);
		notificationIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
		notificationBuilder.setContentIntent(PendingIntent.getActivity(this, 0, notificationIntent, 0));

		if (status == Status.INIT)
		{
			/* start en/decryption process */
			final PowerManager powerManager = (PowerManager)getSystemService(POWER_SERVICE);
			wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, actionTitle);
			wakeLock.acquire();
			process = new Thread(this);
			process.start();
		}

		/* start a thread to keep ui updated */
		notification = new Thread()
		{
			@Override
			public void run()
			{
				do
				{
					try
					{
						sleep(10);
						if (isInterrupted())
							status = Status.CANCELLED;
						if (status == Status.INIT)
							continue;
						sendNotificationUpdate(notificationBuilder);
					}
					catch (final InterruptedException e)
					{
						status = Status.CANCELLED;
					}
				}
				while (status == Status.RUNNING);
				sendNotificationUpdate(notificationBuilder);
			}
		};
		notification.start();

		return START_STICKY;
	}

	@Override
	public void onDestroy()
	{
		if (status == Status.INIT || status == Status.RUNNING)
		{
			notification.interrupt();
			process.interrupt();
		}
		releaseWakeLock();
		super.onDestroy();
	}

	private void releaseWakeLock()
	{
		if (wakeLock != null && wakeLock.isHeld())
		{
			wakeLock.release();
			wakeLock = null;
		}
	}

	@Override
	public IBinder onBind(final Intent arg0)
	{
		return null;
	}

	public static boolean fileEncrypted(Context context, final Uri uri)
	{
		final ContentResolver cr = context.getContentResolver();
		final DocumentFile documentFile = DocumentFile.fromSingleUri(context, uri);
		if (documentFile.isDirectory())
			return false;
		try (InputStream in = cr.openInputStream(uri))
		{
			final byte[] header = new byte[Long.SIZE / Byte.SIZE];
			for (int i = 0; i < 1; i++)
			{
				int err = in.read(header, 0, header.length);
				if (err < 0 || Convert.longFromBytes(header) != HEADER[i])
					return false;
			}
			return true;
		}
		catch (final IOException ignored)
		{
			return false; // either the file doesn't exists or we can't read it for decrypting
		}
	}

	protected static void closeIgnoreException(final Closeable c)
	{
		try
		{
			if (c != null)
				c.close();
		}
		catch (final IOException ignored)
		{
			/* no nothing */
		}
	}

	private void setKey(final String k)
	{
		final File file = new File(k);
		try (final FileInputStream f = new FileInputStream(file))
		{
			key = new byte[(int)file.length()];
			f.read(key);
		}
		catch (final IOException e)
		{
			status = Status.FAILED_KEY;
		}
	}

	private void sendNotificationUpdate(final NotificationCompat.Builder notificationBuilder)
	{
		final Intent intent = new Intent();
		intent.setAction(actionTitle);
		intent.putExtra("current.offset", current.offset);
		intent.putExtra("current.size", current.size);
		intent.putExtra("total.offset", total.offset);
		intent.putExtra("total.size", total.size);
		intent.putExtra("status", status.name());
		sendBroadcast(intent);

		notificationBuilder.setContentText(status == Status.INIT || status == Status.RUNNING ? total.offset + "/" + total.size : status.toString());
		int pct = 0;
		if (status == Status.SUCCESS)
			pct = 100;
		else if (current.size > 0)
			pct = (int)(100 * current.offset / current.size);
		notificationBuilder.setProgress(100, pct, false);
		((NotificationManager)getSystemService(Context.NOTIFICATION_SERVICE)).notify(0, notificationBuilder.build());
	}
}
