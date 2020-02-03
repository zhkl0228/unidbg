package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;

public class LinuxVirtualSymbol extends Symbol {

    private final LinuxModule module;
    private final long address;

    LinuxVirtualSymbol(String name, LinuxModule module, long address) {
        super(name);
        this.module = module;
        this.address = address;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        return LinuxModule.emulateFunction(emulator, address, args);
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
