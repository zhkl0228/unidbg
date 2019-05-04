package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import cn.banny.emulator.Symbol;

class ExportSymbol extends Symbol {

    private final long address;
    private final Module module;
    final long other;

    ExportSymbol(String name, long address, Module module, long other) {
        super(name);
        this.address = address;
        this.module = module;
        this.other = other;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        return module.callFunction(emulator, getValue(), args);
    }

    @Override
    public long getAddress() {
        return module.base + getValue();
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
