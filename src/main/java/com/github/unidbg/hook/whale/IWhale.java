package com.github.unidbg.hook.whale;

import com.github.unidbg.Symbol;
import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;

public interface IWhale extends IHook {

    void WInlineHookFunction(long address, ReplaceCallback callback);
    void WInlineHookFunction(Symbol symbol, ReplaceCallback callback);

    /**
     * 当前对android无效，参考：https://github.com/asLody/whale/blob/master/whale/src/whale.cc，只支持苹果
     */
    void WImportHookFunction(String symbol, ReplaceCallback callback);

}
