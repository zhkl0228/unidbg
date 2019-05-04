package cn.banny.emulator.ios;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Symbol;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.MemoryBlock;
import io.kaitai.MachO;

public class MachOSymbol extends Symbol implements cn.banny.emulator.ios.MachO {

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

    private MemoryBlock nameBlock;

    MemoryBlock createNameMemoryBlock(Memory memory) {
        if (nameBlock == null) {
            byte[] name = getName().getBytes();
            nameBlock = memory.malloc(name.length + 1, true);
            nameBlock.getPointer().write(0, name, 0, name.length);
            nameBlock.getPointer().setByte(name.length, (byte) 0);
        }
        return nameBlock;
    }

}
