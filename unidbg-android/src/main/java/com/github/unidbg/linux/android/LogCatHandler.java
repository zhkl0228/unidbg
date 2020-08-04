package com.github.unidbg.linux.android;

public interface LogCatHandler {

    void handleLog(String type, LogCatLevel level, String tag, String text);

}
