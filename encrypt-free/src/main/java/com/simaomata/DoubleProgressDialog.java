package com.simaomata;

/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import android.app.AlertDialog;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.style.StyleSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;

import net.albinoloverats.android.encrypt.free.R;

import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Arrays;

/**
 * <p>A dialog showing a progress indicator and an optional text message or view.
 * Only a text message or a view can be used at the same time.</p>
 * <p>The dialog can be made cancelable on back key press.</p>
 * <p>The progress range is 0..10000.</p>
 */
public class DoubleProgressDialog extends AlertDialog {

	private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("#,##0");
	private static final DecimalFormat RATE_FORMAT = new DecimalFormat("#,##0.00");

	private ProgressBar mProgress;
	private ProgressBar mSecondaryProgress;

	private TextView mProgressNumber;
	private DecimalFormat mProgressNumberFormat = DECIMAL_FORMAT;
	private TextView mProgressPercent;
	private TextView mProgressRate;
	private ProgressRate progressRateCalc = new ProgressRate();
	private NumberFormat mProgressPercentFormat;

	private TextView mSecondaryProgressNumber;
	private TextView mSecondaryProgressPercent;

	private RelativeLayout mSecondaryLayout;

	private int mMax;
	private int mProgressVal;
	private int mSecondaryMax;
	private int mSecondaryProgressVal;
	private int mIncrementBy;
	private int mIncrementSecondaryBy;
	private Drawable mProgressDrawable;
	private Drawable mIndeterminateDrawable;
	private CharSequence mMessage;
	private boolean mIndeterminate;

	private boolean mHasStarted;
	private Handler mViewUpdateHandler;

	private Context mContext;

	public DoubleProgressDialog(Context context) {
		super(context);

		this.mContext = context;
	}

	public DoubleProgressDialog(Context context, int theme) {
		super(context, theme);
		this.mContext = context;
	}

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		LayoutInflater inflater = LayoutInflater.from(mContext);

		/* Use a separate handler to update the text views as they
		 * must be updated on the same thread that created them.
		 */
		mViewUpdateHandler = new Handler() {
			@Override
			public void handleMessage(Message msg) {
				super.handleMessage(msg);

				/* Update the number and percent */
				int progress = mProgress.getProgress();
				int max = mProgress.getMax();
				double percent = (double) progress / (double) max;
				DecimalFormat format = mProgressNumberFormat;
				mProgressNumber.setText(format.format(progress) + '/' + format.format(max));
				SpannableString tmp = new SpannableString(mProgressPercentFormat.format(percent));
				tmp.setSpan(new StyleSpan(android.graphics.Typeface.BOLD),
					0, tmp.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
				mProgressPercent.setText(tmp);

				double rate = progressRateCalc.calcRate(progress);
				if (Double.isNaN(rate) || rate < 0.0)
					mProgressRate.setText("---.-- B/s");
				else
				{
					String units = "B/s";
					if (rate < 1000.0)
						; // Do nothing
					else if (rate < 1000000.0)
					{
						rate /= 1024;
						units = "KB/s";
					}
					else if (rate < 1000000000.0)
					{
						rate /= (1024 * 1024);
						units = "MB/s";
					}
					else if (rate < 1000000000000.0)
					{
						rate /= (1024 * 1024 * 1024);
						units = "GB/s";
					}
					mProgressRate.setText(RATE_FORMAT.format(rate) + " " + units);
				}

				/* Update the number and percent of the second bar */
				progress = mSecondaryProgress.getProgress();
				max = mSecondaryProgress.getMax(); // Use the same max a the top bar
				percent = (double) progress / (double) max;
				mSecondaryProgressNumber.setText(format.format(progress) + '/' + format.format(max));
				tmp = new SpannableString(mProgressPercentFormat.format(percent));
				tmp.setSpan(new StyleSpan(android.graphics.Typeface.BOLD),
					0, tmp.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
				mSecondaryProgressPercent.setText(tmp);
			}
		};
		View view = inflater.inflate(R.layout.alert_dialog_double_progress, null);
		mProgress = (ProgressBar) view.findViewById(R.id.progress);
		mSecondaryProgress = (ProgressBar) view.findViewById(R.id.secondaryProgress);

		mProgressNumber = (TextView) view.findViewById(R.id.progress_number);
		mProgressNumberFormat = DECIMAL_FORMAT;
		mProgressPercent = (TextView) view.findViewById(R.id.progress_percent);
		mProgressPercentFormat = NumberFormat.getPercentInstance();
		mProgressPercentFormat.setMaximumFractionDigits(0);
		mProgressRate = (TextView) view.findViewById(R.id.progress_rate);

		mSecondaryProgressNumber = (TextView) view.findViewById(R.id.secondary_progress_number);
		mSecondaryProgressPercent = (TextView) view.findViewById(R.id.secondary_progress_percent);

		mSecondaryLayout = (RelativeLayout)view.findViewById(R.id.secondaryLayout);
		hideSecondaryProgress();

		setView(view);

		if (mMax > 0) {
			setMax(mMax);
		}
		if (mProgressVal > 0) {
			setProgress(mProgressVal);
		}
		if (mSecondaryProgressVal > 0) {
			setSecondaryProgress(mSecondaryProgressVal);
		}
		if (mIncrementBy > 0) {
			incrementProgressBy(mIncrementBy);
		}
		if (mIncrementSecondaryBy > 0) {
			incrementSecondaryProgressBy(mIncrementSecondaryBy);
		}
		if (mProgressDrawable != null) {
			setProgressDrawable(mProgressDrawable);
		}
		if (mIndeterminateDrawable != null) {
			setIndeterminateDrawable(mIndeterminateDrawable);
		}
		if (mMessage != null) {
			setMessage(mMessage);
		}
		setIndeterminate(mIndeterminate);
		onProgressChanged();
		super.onCreate(savedInstanceState);
	}

	@Override
	public void onStart() {
		super.onStart();
		mHasStarted = true;
	}

	@Override
	protected void onStop() {
		super.onStop();
		mHasStarted = false;
	}

	public void setProgress(int value) {
		if (mHasStarted) {
			mProgress.setProgress(value);
			onProgressChanged();
		} else {
			mProgressVal = value;
		}
	}

	public int getProgress() {
		if (mProgress != null) {
			return mProgress.getProgress();
		}
		return mProgressVal;
	}

	public void setSecondaryProgress(int secondaryProgress) {
		if (mSecondaryProgress != null) {
			mSecondaryProgress.setProgress(secondaryProgress);
			onProgressChanged();
		} else {
			mSecondaryProgressVal = secondaryProgress;
		}
	}

	public int getSecondaryProgress() {
		if (mSecondaryProgress != null) {
			// We only use the secondary progress on the second bar
			// Seems to be more usable that way..
			return mSecondaryProgress.getProgress();
		}
		return mSecondaryProgressVal;
	}

	public int getMax() {
		if (mProgress != null) {
			return mProgress.getMax();
		}
		return mMax;
	}

	public void setMax(int max) {
		if (mProgress != null) {
			mProgress.setMax(max);
			onProgressChanged();
		} else {
			mMax = max;
		}
	}

	public int getSecondaryMax() {
		if (mSecondaryProgress != null) {
			return mSecondaryProgress.getMax();
		}
		return mSecondaryMax;
	}

	public void setSecondaryMax(int max) {
		if (mSecondaryProgress != null) {
			mSecondaryProgress.setMax(max);
			onProgressChanged();
		} else {
			mSecondaryMax = max;
		}
	}

	public void incrementProgressBy(int diff) {
		if (mProgress != null) {
			mProgress.incrementProgressBy(diff);
			onProgressChanged();
		} else {
			mIncrementBy += diff;
		}
	}

	public void incrementSecondaryProgressBy(int diff) {
		if (mSecondaryProgress != null) {
			mSecondaryProgress.incrementProgressBy(diff);
			onProgressChanged();
		} else {
			mIncrementSecondaryBy += diff;
		}
	}

	public void setProgressDrawable(Drawable d) {
		if (mProgress != null) {
			mProgress.setProgressDrawable(d);
		} else {
			mProgressDrawable = d;
		}
	}

	public void setIndeterminateDrawable(Drawable d) {
		if (mProgress != null) {
			mProgress.setIndeterminateDrawable(d);
		} else {
			mIndeterminateDrawable = d;
		}
	}

	public void setIndeterminate(boolean indeterminate) {
		if (mProgress != null) {
			mProgress.setIndeterminate(indeterminate);
		} else {
			mIndeterminate = indeterminate;
		}
	}

	public boolean isIndeterminate() {
		if (mProgress != null) {
			return mProgress.isIndeterminate();
		}
		return mIndeterminate;
	}

	@Override
	public void setMessage(CharSequence message) {
		if (mProgress != null) {
				super.setMessage(message);
		} else {
			mMessage = message;
		}
	}

	/**
	 * Change the format of Progress Number. The default is "current/max".
	 * Should not be called during the number is progressing.
	 * @param format Should contain two "%d". The first is used for current number
	 * and the second is used for the maximum.
	 * @hide
	 */
	public void setProgressNumberFormat(String format) {
		mProgressNumberFormat = new DecimalFormat(format);
	}

	public void setProgressNumberFormat(DecimalFormat format) {
		mProgressNumberFormat = format;
	}

	private void onProgressChanged() {
		mViewUpdateHandler.sendEmptyMessage(0);
	}

	public void showSecondaryProgress()
	{
		mSecondaryLayout.setVisibility(View.VISIBLE);
	}

	public void hideSecondaryProgress()
	{
		mSecondaryLayout.setVisibility(View.GONE);
	}

	private class ProgressRate
	{
		private static final int BPS = 128;

		private final Rate[] rate = new Rate[BPS];// = new Rate();
		private int next = 0;

		public ProgressRate()
		{
			for (int j = 0; j < BPS; j++)
				rate[j] = new Rate();
		}

		public double calcRate(final int r)
		{
			rate[next].bytes = r;
			rate[next].time = System.currentTimeMillis();
			final Rate[] copy = Arrays.copyOf(rate, BPS);
			Arrays.sort(copy);
			double avg[] = new double[BPS];
			for (int i = 1; i < BPS; i++)
			{
				if (copy[i].time == 0)
					continue;
				avg[i - 1] = 1000.0 * (double)(copy[i].bytes - copy[i - 1].bytes) / (double)(copy[i].time - copy[i - 1].time);
			}
			double v = 0.0;
			int c = BPS - 1;
			for (int i = 0; i < BPS - 1; i++)
				if (Double.isInfinite(avg[i]) || Double.isNaN(avg[i]))
					c--;
				else
					v += avg[i];
			if (next++ >= BPS - 1)
				next = 0;
			return v / c;
		}

		private class Rate implements Comparable<Rate>
		{
			int bytes;
			long time;

			@Override
			public int compareTo(final Rate another)
			{
				return (int)(time - another.time);
			}
		}
	}
}
