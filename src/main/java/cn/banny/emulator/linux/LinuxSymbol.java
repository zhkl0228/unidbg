package cn.banny.emulator.linux;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import net.fornwall.jelf.ElfSymbol;

public class LinuxSymbol extends Symbol {

    private final LinuxModule module;
    private final ElfSymbol elfSymbol;

    LinuxSymbol(LinuxModule module, ElfSymbol elfSymbol) {
        this.module = module;
        this.elfSymbol = elfSymbol;
    }

    @Override
    public boolean isUndef() {
        return elfSymbol.isUndef();
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        return module.callFunction(emulator, elfSymbol.value, args);
    }

    @Override
    public long getAddress() {
        return module.base + elfSymbol.value;
    }

}
