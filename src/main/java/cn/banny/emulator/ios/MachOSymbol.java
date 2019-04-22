package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import io.kaitai.MachO;

public class MachOSymbol extends Symbol {

    private final MachOModule module;
    private final MachO.SymtabCommand.Nlist nlist;

    MachOSymbol(MachOModule module, MachO.SymtabCommand.Nlist nlist, String name) {
        super(name);

        this.module = module;
        this.nlist = nlist;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        return module.callFunction(emulator, nlist.value(), args);
    }

    @Override
    public long getAddress() {
        return module.base + nlist.value();
    }

    @Override
    public boolean isUndef() {
        return false;
    }

}
