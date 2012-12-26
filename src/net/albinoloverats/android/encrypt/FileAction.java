package net.albinoloverats.android.encrypt;

public enum FileAction
{
    LOAD(0),
    SAVE(1);

    public int value;

    private FileAction(final int value)
    {
        this.value = value;
    }

    public static FileAction fromValue(final int value)
    {
        for (final FileAction action : FileAction.values())
            if (action.value == value)
                return action;
        return null;
    }
}
