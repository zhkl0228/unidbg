package com.github.unidbg.virtualmodule;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

public final class VirtualSymbol extends Symbol {

    private final Module module;
    private final long address;

    public VirtualSymbol(String name, Module module, long address) {
        super(name);
        this.module = module;
        this.address = address;
    }

    @Override
    public Number[] call(Emulator<?> emulator, Object... args) {
        return Module.emulateFunction(emulator, address, args);
    }

    @Override
    public long getAddress() {
        return address;
    }

    @Override
    public long getValue() {
        return address - module.base;
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
