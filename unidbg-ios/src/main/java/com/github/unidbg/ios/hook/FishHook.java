package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.fishhook.IFishHook;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FishHook extends BaseHook implements IFishHook {

    private static final Logger log = LoggerFactory.getLogger(FishHook.class);

    public static IFishHook getInstance(Emulator<?> emulator) {
        IFishHook fishHook = emulator.get(FishHook.class.getName());
        if (fishHook == null) {
            fishHook = new FishHook(emulator);
            emulator.set(FishHook.class.getName(), fishHook);
        }
        return fishHook;
    }

    private final Symbol rebind_symbols, rebind_symbols_image;

    private FishHook(Emulator<?> emulator) {
        super(emulator, "libfishhook");

        rebind_symbols = module.findSymbolByName("_rebind_symbols", false);
        rebind_symbols_image = module.findSymbolByName("_rebind_symbols_image", false);
        if (log.isDebugEnabled()) {
            log.debug("rebind_symbols={}, rebind_symbols_image={}", rebind_symbols, rebind_symbols_image);
        }

        if (rebind_symbols == null) {
            throw new IllegalStateException("rebind_symbols is null");
        }

        if (rebind_symbols_image == null) {
            throw new IllegalStateException("rebind_symbols_image is null");
        }
    }

    @Override
    public void rebindSymbol(String symbol, ReplaceCallback callback) {
        rebindSymbol(symbol, callback, false);
    }

    @Override
    public void rebindSymbol(String symbol, ReplaceCallback callback, boolean enablePostCall) {
        Pointer rebinding = createRebinding(symbol, callback, enablePostCall);
        int ret = rebind_symbols.call(emulator, rebinding, 1).intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }

    private Pointer createRebinding(String symbol, ReplaceCallback callback, boolean enablePostCall) {
        Memory memory = emulator.getMemory();
        Pointer symbolPointer = memory.malloc(symbol.length() + 1, false).getPointer();
        symbolPointer.setString(0, symbol);

        final Pointer originCall = memory.malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replaceCall = createReplacePointer(callback, originCall, enablePostCall);

        Pointer rebinding = memory.malloc(emulator.getPointerSize() * 3, false).getPointer();
        rebinding.setPointer(0, symbolPointer);
        rebinding.setPointer(emulator.getPointerSize(), replaceCall);
        rebinding.setPointer(2L * emulator.getPointerSize(), originCall);
        return rebinding;
    }

    @Override
    public void rebindSymbolImage(Module module, String symbol, ReplaceCallback callback) {
        rebindSymbolImage(module, symbol, callback, false);
    }

    @Override
    public void rebindSymbolImage(Module module, String symbol, ReplaceCallback callback, boolean enablePostCall) {
        MachOModule mm = (MachOModule) module;
        long header = mm.machHeader;
        long slide = mm.slide;
        Pointer rebinding = createRebinding(symbol, callback, enablePostCall);
        int ret = rebind_symbols_image.call(emulator, UnidbgPointer.pointer(emulator, header), UnidbgPointer.pointer(emulator, slide), rebinding, 1).intValue();
        if (ret != RET_SUCCESS) {
            throw new IllegalStateException("ret=" + ret);
        }
    }
}
