package com.github.unidbg.hook;

import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;

public interface InlineHook {

    void replace(long functionAddress, ReplaceCallback callback);
    void replace(Symbol symbol, ReplaceCallback callback);

    void replace(long functionAddress, Svc replace);
    void replace(Symbol symbol, Svc replace);

    void replace(long functionAddress, ReplaceCallback callback, boolean enablePostCall);
    void replace(Symbol symbol, ReplaceCallback callback, boolean enablePostCall);

}
