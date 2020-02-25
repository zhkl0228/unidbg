package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import io.kaitai.MachO;

public class MachOSymbol extends Symbol implements com.github.unidbg.ios.MachO {

    private final MachOModule module;
    final MachO.SymtabCommand.Nlist nlist;

    MachOSymbol(MachOModule module, MachO.SymtabCommand.Nlist nlist, String name) {
        super(name);

        this.module = module;
        this.nlist = nlist;
    }

    @Override
    public Number[] call(Emulator<?> emulator, Object... args) {
        return module.callFunction(emulator, getValue(), args);
    }

    @Override
    public long getAddress() {
        return module.base + getValue();
    }

    @Override
    public long getValue() {
        boolean isThumb = (nlist.desc() & N_ARM_THUMB_DEF) != 0;
        return nlist.value() + (isThumb ? 1 : 0);
    }

    @Override
    public boolean isUndef() {
        return false;
    }

    @Override
    public String getModuleName() {
        return module.name;
    }

}
