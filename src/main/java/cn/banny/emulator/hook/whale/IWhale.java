package cn.banny.emulator.hook.whale;

import cn.banny.emulator.Symbol;
import cn.banny.emulator.hook.ReplaceCallback;

public interface IWhale {

    void WInlineHookFunction(long address, ReplaceCallback callback);
    void WInlineHookFunction(Symbol symbol, ReplaceCallback callback);

    /**
     * 当前对android无效，参考：https://github.com/asLody/whale/blob/master/whale/src/whale.cc，只支持苹果
     */
    void WImportHookFunction(String symbol, ReplaceCallback callback);

}
