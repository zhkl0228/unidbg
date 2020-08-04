package com.github.unidbg.linux.android;

public enum LogCatLevel {

    /**
     * Priority constant for the println method; use Log.v.
     */
    VERBOSE(2, 'V'),

    /**
     * Priority constant for the println method; use Log.d.
     */
    DEBUG(3, 'D'),

    /**
     * Priority constant for the println method; use Log.i.
     */
    INFO(4, 'I'),

    /**
     * Priority constant for the println method; use Log.w.
     */
    WARN(5, 'W'),

    /**
     * Priority constant for the println method; use Log.e.
     */
    ERROR(6, 'E'),

    /**
     * Priority constant for the println method.
     */
    ASSERT(7, 'A');

    private final int value;
    private final char level;

    LogCatLevel(int value, char level) {
        this.value = value;
        this.level = level;
    }

    public char getLevel() {
        return level;
    }

    @Override
    public String toString() {
        return Character.toString(level);
    }

    public static LogCatLevel valueOf(int value) {
        for (LogCatLevel level : values()) {
            if (level.value == value) {
                return level;
            }
        }
        return null;
    }

}
