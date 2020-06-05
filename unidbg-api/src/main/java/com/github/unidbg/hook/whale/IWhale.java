package com.github.unidbg.hook.whale;

import com.github.unidbg.Symbol;
import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;

public interface IWhale extends IHook {

    void inlineHookFunction(long address, ReplaceCallback callback);
    void inlineHookFunction(Symbol symbol, ReplaceCallback callback);

    void inlineHookFunction(long address, ReplaceCallback callback, boolean enablePostCall);
    @SuppressWarnings("unused")
    void inlineHookFunction(Symbol symbol, ReplaceCallback callback, boolean enablePostCall);

    /**
     * 当前对android无效，参考：https://github.com/asLody/whale/blob/master/whale/src/whale.cc，只支持苹果
     */
    @SuppressWarnings("unused")
    void importHookFunction(String symbol, ReplaceCallback callback);
    void importHookFunction(String symbol, ReplaceCallback callback, boolean enablePostCall);

}
