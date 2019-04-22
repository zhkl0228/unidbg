package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import io.kaitai.MachO;

public class MachOSymbol extends Symbol {

    private static final int N_ARM_THUMB_DEF = 0x8;

    private final MachOModule module;
    private final MachO.SymtabCommand.Nlist nlist;

    MachOSymbol(MachOModule module, MachO.SymtabCommand.Nlist nlist, String name) {
        super(name);

        this.module = module;
        this.nlist = nlist;
    }

    @Override
    public Number[] call(Emulator emulator, Object... args) {
        return module.callFunction(emulator, getValue(), args);
    }

    @Override
    public long getAddress() {
        return module.base + getValue();
    }

    private long getValue() {
        boolean isThumb = nlist.desc() == N_ARM_THUMB_DEF;
        return nlist.value() + (isThumb ? 1 : 0);
    }

    @Override
    public boolean isUndef() {
        return false;
    }

}
