package com.github.unidbg.hook.xhook;

import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;

/**
 * Only support android
 */
public interface IxHook extends IHook {

    int RET_SUCCESS = 0;

    void register(String pathname_regex_str, String symbol, ReplaceCallback callback);
    void register(String pathname_regex_str, String symbol, ReplaceCallback callback, boolean enablePostCall);

    void refresh();

}
