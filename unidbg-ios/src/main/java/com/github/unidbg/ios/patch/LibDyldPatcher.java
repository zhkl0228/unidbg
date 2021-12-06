package com.github.unidbg.ios.patch;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.ModulePatcher;
import com.sun.jna.Pointer;

public class LibDyldPatcher extends ModulePatcher {

    private final Pointer _NSGetArgc;
    private final Pointer _NSGetArgv;
    private final Pointer _NSGetEnviron;
    private final Pointer _NSGetProgname;

    public LibDyldPatcher(Pointer _NSGetArgc, Pointer _NSGetArgv, Pointer _NSGetEnviron, Pointer _NSGetProgname) {
        super("/usr/lib/system/libdyld.dylib");
        this._NSGetArgc = _NSGetArgc;
        this._NSGetArgv = _NSGetArgv;
        this._NSGetEnviron = _NSGetEnviron;
        this._NSGetProgname = _NSGetProgname;
    }

    @Override
    protected void patch32(Emulator<?> emulator, Module module) {
        patch(emulator, module);
    }

    private void setSymbolPointer(Emulator<?> emulator, Symbol symbol, Pointer pointer) {
        Pointer ptr = UnidbgPointer.pointer(emulator, symbol.getAddress());
        assert ptr != null;
        ptr.setPointer(0, pointer.getPointer(0));
    }

    @Override
    protected void patch64(Emulator<?> emulator, Module module) {
        patch(emulator, module);
    }

    private void patch(Emulator<?> emulator, Module module) {
        Symbol _NXArgc = module.findSymbolByName("_NXArgc", false);
        setSymbolPointer(emulator, _NXArgc, _NSGetArgc);

        Symbol _NXArgv = module.findSymbolByName("_NXArgv", false);
        setSymbolPointer(emulator, _NXArgv, _NSGetArgv);

        Symbol _environ = module.findSymbolByName("_environ", false);
        setSymbolPointer(emulator, _environ, _NSGetEnviron);

        Symbol ___progname = module.findSymbolByName("___progname", false);
        setSymbolPointer(emulator, ___progname, _NSGetProgname);
    }
}
