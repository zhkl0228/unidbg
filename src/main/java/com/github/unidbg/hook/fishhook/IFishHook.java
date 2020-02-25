package com.github.unidbg.hook.fishhook;

import com.github.unidbg.Module;
import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;

/**
 * Only support iOS
 */
public interface IFishHook extends IHook {

    int RET_SUCCESS = 0;

    /**
     * For each rebinding in rebindings, rebinds references to external, indirect
     * symbols with the specified name to instead point at replacement for each
     * image in the calling process as well as for all future images that are loaded
     * by the process. If rebind_functions is called more than once, the symbols to
     * rebind are added to the existing list of rebindings, and if a given symbol
     * is rebound more than once, the later rebinding will take precedence.
     */
    @SuppressWarnings("unused")
    void rebindSymbol(String symbol, ReplaceCallback callback);
    void rebindSymbol(String symbol, ReplaceCallback callback, boolean enablePostCall);

    /**
     * Rebinds as above, but only in the specified image. The header should point
     * to the mach-o header, the slide should be the slide offset. Others as above.
     */
    void rebindSymbolImage(Module module, String symbol, ReplaceCallback callback);
    void rebindSymbolImage(Module module, String symbol, ReplaceCallback callback, boolean enablePostCall);

}
