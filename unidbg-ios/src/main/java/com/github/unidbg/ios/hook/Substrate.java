package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Substrate extends BaseHook implements ISubstrate {

    private static final Log log = LogFactory.getLog(Substrate.class);

    public static ISubstrate getInstance(Emulator<?> emulator) {
        Substrate substrate = emulator.get(Substrate.class.getName());
        if (substrate == null) {
            substrate = new Substrate(emulator);
            emulator.set(Substrate.class.getName(), substrate);
        }
        return substrate;
    }

    private final Symbol _MSGetImageByName;
    private final Symbol _MSFindSymbol;
    private final Symbol _MSHookFunction;
    private final Symbol _MSHookMessageEx;

    private Substrate(Emulator<?> emulator) {
        super(emulator, "libsubstrate");

        _MSGetImageByName = module.findSymbolByName("_MSGetImageByName", false);
        _MSFindSymbol = module.findSymbolByName("_MSFindSymbol", false);
        _MSHookFunction = module.findSymbolByName("_MSHookFunction", false);
        _MSHookMessageEx = module.findSymbolByName("_MSHookMessageEx", false);

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
            log.debug("_MSGetImageByName=" + UnidbgPointer.pointer(emulator, _MSGetImageByName.getAddress()) + ", _MSFindSymbol=" + UnidbgPointer.pointer(emulator, _MSFindSymbol.getAddress()) + ", _MSHookFunction=" + UnidbgPointer.pointer(emulator, _MSHookFunction.getAddress()) + ", _MSHookMessageEx=" + UnidbgPointer.pointer(emulator, _MSHookMessageEx.getAddress()) + ", _MSDebug=" + UnidbgPointer.pointer(emulator, _MSDebug.getAddress()));
        }

        if (log.isDebugEnabled()) {
            _MSDebug.createPointer(emulator).setInt(0, 1);
        }
    }

    @Override
    public Module getImageByName(String file) {
        Number[] numbers = _MSGetImageByName.call(emulator, file);
        long ret = numberToAddress(numbers[0]);
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
        Number[] numbers = _MSFindSymbol.call(emulator, mm == null ? null : UnidbgPointer.pointer(emulator, mm.machHeader), name);
        long ret = numberToAddress(numbers[0]);
        if (ret == 0) {
            return null;
        } else {
            return new SubstrateSymbol(name, ret);
        }
    }

    @Override
    public void hookFunction(Symbol symbol, ReplaceCallback callback) {
        hookFunction(symbol, callback, false);
    }

    @Override
    public void hookFunction(long address, ReplaceCallback callback) {
        hookFunction(address, callback, false);
    }

    @Override
    public void hookFunction(Symbol symbol, ReplaceCallback callback, boolean enablePostCall) {
        hookFunction(symbol.getAddress(), callback, enablePostCall);
    }

    @Override
    public void hookFunction(long address, ReplaceCallback callback, boolean enablePostCall) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup, enablePostCall);
        _MSHookFunction.call(emulator, UnidbgPointer.pointer(emulator, address), replace, backup);
    }

    @Override
    public void hookMessageEx(Pointer _class, Pointer message, ReplaceCallback callback) {
        hookMessageEx(_class, message, callback, false);
    }

    @Override
    public void hookMessageEx(ObjcClass _class, Pointer message, ReplaceCallback callback) {
        hookMessageEx(_class.getPointer(), message, callback);
    }

    @Override
    public void hookMessageEx(Pointer _class, Pointer message, ReplaceCallback callback, boolean enablePostCall) {
        final Pointer backup = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer replace = createReplacePointer(callback, backup, enablePostCall);
        _MSHookMessageEx.call(emulator, _class, message, replace, backup);
    }

    @Override
    public void hookMessageEx(ObjcClass _class, Pointer message, ReplaceCallback callback, boolean enablePostCall) {
        hookMessageEx(_class.getPointer(), message, callback, enablePostCall);
    }
}
