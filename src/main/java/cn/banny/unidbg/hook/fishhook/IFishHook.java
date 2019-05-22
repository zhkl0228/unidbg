package cn.banny.unidbg.hook.fishhook;

import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.ios.MachOModule;

/**
 * Only support iOS
 */
public interface IFishHook {

    int RET_SUCCESS = 0;

    /**
     * For each rebinding in rebindings, rebinds references to external, indirect
     * symbols with the specified name to instead point at replacement for each
     * image in the calling process as well as for all future images that are loaded
     * by the process. If rebind_functions is called more than once, the symbols to
     * rebind are added to the existing list of rebindings, and if a given symbol
     * is rebound more than once, the later rebinding will take precedence.
     */
    void rebindSymbol(String symbol, ReplaceCallback callback);

    /**
     * Rebinds as above, but only in the specified image. The header should point
     * to the mach-o header, the slide should be the slide offset. Others as above.
     */
    void rebindSymbolImage(MachOModule module, String symbol, ReplaceCallback callback);

}
