package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;

class ExportSymbol extends Symbol {

    private final long address;
    private final Module module;

    ExportSymbol(String name, long address, Module module) {
        super(name);
        this.address = address;
        this.module = module;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }

    @Override
    public String getModuleName() {
        return module.name;
    }
}
