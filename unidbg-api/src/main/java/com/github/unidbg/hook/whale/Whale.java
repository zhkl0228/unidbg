package com.github.unidbg.hook.whale;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class Whale extends BaseHook implements IWhale {

    private static final Log log = LogFactory.getLog(Whale.class);

    public static IWhale getInstance(Emulator<?> emulator) {
        IWhale whale = emulator.get(Whale.class.getName());
        if (whale == null) {
            try {
                whale = new Whale(emulator);
                emulator.set(Whale.class.getName(), whale);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return whale;
    }

    private final Symbol WInlineHookFunction, WImportHookFunction;

    private Whale(Emulator<?> emulator) throws IOException {
        super(emulator, "libwhale");

        boolean isIOS = ".dylib".equals(emulator.getLibraryExtension());
        WInlineHookFunction = module.findSymbolByName(isIOS ? "_WInlineHookFunction" : "WInlineHookFunction", false);
        WImportHookFunction = module.findSymbolByName(isIOS ? "_WImportHookFunction" : "WImportHookFunction", false);
        if (log.isDebugEnabled()) {
            log.debug("WInlineHookFunction=" + WInlineHookFunction + ", WImportHookFunction=" + WImportHookFunction);
        }

        if (WInlineHookFunction == null) {
            throw new IllegalStateException("WInlineHookFunction is null");
        }
        if (WImportHookFunction == null) {
            throw new IllegalStateException("WImportHookFunction is null");
        }
    }

    @Override
    public void inlineHookFunction(long address, final ReplaceCallback callback) {
        inlineHookFunction(address, callback, false);
    }

    @Override
    public void inlineHookFunction(Symbol symbol, ReplaceCallback callback) {
        inlineHookFunction(symbol.getAddress(), callback);
    }

    @Override
    public void inlineHookFunction(long address, ReplaceCallback callback, boolean enablePostCall) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup, enablePostCall);
        WInlineHookFunction.call(emulator, UnicornPointer.pointer(emulator, address), replace, backup);
    }

    @Override
    public void inlineHookFunction(Symbol symbol, ReplaceCallback callback, boolean enablePostCall) {
        inlineHookFunction(symbol.getAddress(), callback, enablePostCall);
    }

    @Override
    public void importHookFunction(String symbol, final ReplaceCallback callback) {
        importHookFunction(symbol, callback, false);
    }

    @Override
    public void importHookFunction(String symbol, ReplaceCallback callback, boolean enablePostCall) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup, enablePostCall);
        WImportHookFunction.call(emulator, symbol, null, replace, backup);
    }
}
