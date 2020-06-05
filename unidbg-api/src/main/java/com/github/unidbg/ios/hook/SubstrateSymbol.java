package com.github.unidbg.ios.hook;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

class SubstrateSymbol extends Symbol {

    private final long address;

    SubstrateSymbol(String name, long address) {
        super(name);
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
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isUndef() {
        return false;
    }

    @Override
    public String getModuleName() {
        throw new UnsupportedOperationException();
    }

}
