package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

public class Substrate extends BaseHook implements ISubstrate {

    private static final Log log = LogFactory.getLog(Substrate.class);

    public static ISubstrate getInstance(Emulator emulator) {
        Substrate substrate = emulator.get(Substrate.class.getName());
        if (substrate == null) {
            try {
                substrate = new Substrate(emulator);
                emulator.set(Substrate.class.getName(), substrate);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return substrate;
    }

    private final Symbol _MSGetImageByName;
    private final Symbol _MSFindSymbol;
    private final Symbol _MSHookFunction;
    private final Symbol _MSHookMessageEx;

    private Substrate(Emulator emulator) throws IOException {
        super(emulator, "libsubstrate");

        _MSGetImageByName = module.findSymbolByName("_MSGetImageByName", false);
        _MSFindSymbol = module.findSymbolByName("_MSFindSymbol", false);
        _MSHookFunction = module.findSymbolByName("_MSHookFunction", false);
        _MSHookMessageEx = module.findSymbolByName("_MSHookMessageEx", false);
        log.debug("_MSGetImageByName=" + _MSGetImageByName + ", _MSFindSymbol=" + _MSFindSymbol + ", _MSHookFunction=" + _MSHookFunction + ", _MSHookMessageEx=" + _MSHookMessageEx);

        if (_MSGetImageByName == null) {
            throw new IllegalStateException("_MSGetImageByName is null");
        }
        if (_MSFindSymbol == null) {
            throw new IllegalStateException("_MSFindSymbol is null");
        }
        if (_MSHookFunction == null) {
            throw new IllegalStateException("_MSHookFunction is null");
        }
        if (_MSHookMessageEx == null) {
            throw new IllegalStateException("_MSHookMessageEx is null");
        }

        Symbol _MSDebug = module.findSymbolByName("_MSDebug", false);
        if (_MSDebug == null) {
            throw new IllegalStateException("_MSDebug is null");
        }

        if (log.isDebugEnabled()) {
            _MSDebug.createPointer(emulator).setInt(0, 1);
        }
    }

    @Override
    public Module getImageByName(String file) {
        Number[] numbers = _MSGetImageByName.call(emulator, file);
        long ret = numbers[0].intValue() & 0xffffffffL;
        if (ret == 0) {
            return null;
        } else {
            for (Module module : emulator.getMemory().getLoadedModules()) {
                MachOModule mm = (MachOModule) module;
                if (mm.machHeader == ret) {
                    return module;
                }
            }
            throw new IllegalStateException("ret=0x" + Long.toHexString(ret));
        }
    }

    @Override
    public Symbol findSymbol(Module image, String name) {
        MachOModule mm = (MachOModule) image;
        Number[] numbers = _MSFindSymbol.call(emulator, (mm == null ? 0 : (int) mm.machHeader), name);
        long ret = numbers[0].intValue() & 0xffffffffL;
        if (ret == 0) {
            return null;
        } else {
            return new SubstrateSymbol(name, ret);
        }
    }

    @Override
    public void hookFunction(Symbol symbol, ReplaceCallback callback) {
        hookFunction(symbol.getAddress(), callback);
    }

    @Override
    public void hookFunction(long address, ReplaceCallback callback) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup);
        _MSHookFunction.call(emulator, UnicornPointer.pointer(emulator, address), replace, backup);
    }

    @Override
    public void hookMessageEx(Pointer _class, Pointer message, ReplaceCallback callback) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup);
        _MSHookMessageEx.call(emulator, _class, message, replace, backup);
    }

}
