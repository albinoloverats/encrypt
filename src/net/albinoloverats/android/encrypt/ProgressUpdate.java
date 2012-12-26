package net.albinoloverats.android.encrypt;

public enum ProgressUpdate
{
    DONE(0),
    TOTAL(1),
    CURRENT(2);

    public int value;

    private ProgressUpdate(final int value)
    {
        this.value = value;
    }

    public static ProgressUpdate fromValue(final int value)
    {
        for (final ProgressUpdate progressUpdate : ProgressUpdate.values())
            if (progressUpdate.value == value)
                return progressUpdate;
        return null;
    }
}
