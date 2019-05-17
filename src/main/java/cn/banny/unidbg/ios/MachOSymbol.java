package cn.banny.unidbg.ios;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Symbol;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import io.kaitai.MachO;

public class MachOSymbol extends Symbol implements cn.banny.unidbg.ios.MachO {

    private final MachOModule module;
    final MachO.SymtabCommand.Nlist nlist;

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

    @Override
    public long getValue() {
        boolean isThumb = (nlist.desc() & N_ARM_THUMB_DEF) != 0;
        return nlist.value() + (isThumb ? 1 : 0);
    }

    @Override
    public boolean isUndef() {
        return false;
    }

    @Override
    public String getModuleName() {
        return module.name;
    }

    private UnicornPointer namePointer;

    UnicornPointer createNameMemory(SvcMemory svcMemory) {
        if (namePointer == null) {
            byte[] name = getName().getBytes();
            namePointer = svcMemory.allocate(name.length + 1);
            namePointer.write(0, name, 0, name.length);
            namePointer.setByte(name.length, (byte) 0);
        }
        return namePointer;
    }

}
