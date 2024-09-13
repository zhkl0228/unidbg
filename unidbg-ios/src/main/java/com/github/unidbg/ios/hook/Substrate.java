package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Svc;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.BaseHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.substrate.ISubstrate;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Substrate extends BaseHook implements ISubstrate {

    private static final Logger log = LoggerFactory.getLogger(Substrate.class);

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
            log.debug("_MSGetImageByName={}, _MSFindSymbol={}, _MSHookFunction={}, _MSHookMessageEx={}, _MSDebug={}", UnidbgPointer.pointer(emulator, _MSGetImageByName.getAddress()), UnidbgPointer.pointer(emulator, _MSFindSymbol.getAddress()), UnidbgPointer.pointer(emulator, _MSHookFunction.getAddress()), UnidbgPointer.pointer(emulator, _MSHookMessageEx.getAddress()), UnidbgPointer.pointer(emulator, _MSDebug.getAddress()));
        }

        if (log.isDebugEnabled()) {
            _MSDebug.createPointer(emulator).setInt(0, 1);
        }
    }

    @Override
    public Module getImageByName(String file) {
        Number number = _MSGetImageByName.call(emulator, file);
        long ret = number.longValue();
        if (emulator.is32Bit()) {
            ret &= 0xffffffffL;
        }
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
        Number number = _MSFindSymbol.call(emulator, mm == null ? null : UnidbgPointer.pointer(emulator, mm.machHeader), name);
        long ret = number.longValue();
        if (emulator.is32Bit()) {
            ret &= 0xffffffffL;
        }
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
    public void replace(long functionAddress, Svc svc) {
        if (svc == null) {
            throw new NullPointerException();
        }
        final Pointer originCall = emulator.getMemory().malloc(emulator.getPointerSize(), false).getPointer();
        Pointer callback = emulator.getSvcMemory().registerSvc(svc);
        _MSHookFunction.call(emulator, UnidbgPointer.pointer(emulator, functionAddress), callback, originCall);
    }

    @Override
    public void replace(Symbol symbol, Svc svc) {
        replace(symbol.getAddress(), svc);
    }

    @Override
    public void replace(long functionAddress, ReplaceCallback callback) {
        hookFunction(functionAddress, callback);
    }

    @Override
    public void replace(Symbol symbol, ReplaceCallback callback) {
        hookFunction(symbol, callback);
    }

    @Override
    public void replace(long functionAddress, ReplaceCallback callback, boolean enablePostCall) {
        hookFunction(functionAddress, callback, enablePostCall);
    }

    @Override
    public void replace(Symbol symbol, ReplaceCallback callback, boolean enablePostCall) {
        hookFunction(symbol, callback, enablePostCall);
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
