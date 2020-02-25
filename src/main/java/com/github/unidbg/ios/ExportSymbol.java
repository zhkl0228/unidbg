package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

class ExportSymbol extends Symbol {

    private final long address;
    private final Module module;
    final long other;
    final boolean absolute;

    ExportSymbol(String name, long address, Module module, long other, boolean absolute) {
        super(name);
        this.address = address;
        this.module = module;
        this.other = other;
        this.absolute = absolute;
    }

    @Override
    public Number[] call(Emulator<?> emulator, Object... args) {
        return module.callFunction(emulator, getValue(), args);
    }

    @Override
    public long getAddress() {
        if (absolute) {
            return getValue();
        } else {
            return module.base + getValue();
        }
    }

    @Override
    public long getValue() {
        return address;
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
