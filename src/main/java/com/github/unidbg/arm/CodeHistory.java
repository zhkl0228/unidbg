package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.Emulator;
import unicorn.Unicorn;

public class CodeHistory {

    public final long address;
    private final int size;
    final boolean thumb;
    CodeHistory(long address, int size, boolean thumb) {
        this.address = address;
        this.size = size;
        this.thumb = thumb;
    }

    Capstone.CsInsn disassemble(Emulator<?> emulator) {
        Unicorn u = emulator.getUnicorn();
        byte[] code = u.mem_read(address, size);
        return emulator.disassemble(address, code, thumb, 1)[0];
    }

}
