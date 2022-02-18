package com.github.unidbg.linux.struct;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

public abstract class IFConf extends UnidbgStructure {

    public static IFConf create(Emulator<?> emulator, Pointer pointer) {
        return emulator.is64Bit() ? new IFConf64(pointer) : new IFConf32(pointer);
    }

    public int ifc_len;

    public IFConf(Pointer p) {
        super(p);
    }

    public abstract long getIfcuReq();

}
