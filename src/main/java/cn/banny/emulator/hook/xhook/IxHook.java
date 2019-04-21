package cn.banny.emulator.hook.xhook;

import cn.banny.emulator.hook.ReplaceCallback;

/**
 * Only support android
 */
public interface IxHook {

    int RET_SUCCESS = 0;

    void register(String pathname_regex_str, String symbol, ReplaceCallback callback);

    void refresh();

}
