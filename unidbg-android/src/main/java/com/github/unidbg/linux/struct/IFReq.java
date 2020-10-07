package com.github.unidbg.linux.struct;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public abstract class IFReq extends UnidbgStructure {

    static final int IFNAMSIZ = 16;

    public static IFReq createIFReq(Emulator<?> emulator, Pointer pointer) {
        return emulator.is64Bit() ? new IFReq64(pointer) : new IFReq32(pointer);
    }

    IFReq(Pointer p) {
        super(p);
    }

    public Pointer getAddrPointer() {
        return getPointer().share(IFNAMSIZ);
    }

    public void setName(String name) {
        byte[] data = name.getBytes(StandardCharsets.UTF_8);
        if (data.length >= IFNAMSIZ) {
            throw new IllegalStateException("name=" + name);
        }
        ifrn_name = Arrays.copyOf(data, IFNAMSIZ);
    }

    public byte[] ifrn_name = new byte[IFNAMSIZ];

}
