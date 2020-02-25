package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import net.fornwall.jelf.ElfSymbol;

import java.io.IOException;

public class LinuxSymbol extends Symbol {

    private final LinuxModule module;
    private final ElfSymbol elfSymbol;

    LinuxSymbol(LinuxModule module, ElfSymbol elfSymbol) throws IOException {
        super(elfSymbol.getName());
        this.module = module;
        this.elfSymbol = elfSymbol;
    }

    @Override
    public boolean isUndef() {
        return elfSymbol.isUndef();
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
        return elfSymbol.value;
    }

    @Override
    public String getModuleName() {
        return module.name;
    }
}
