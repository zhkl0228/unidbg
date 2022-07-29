package com.github.unidbg.arm;

import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;

public class CodeHistory {

    public final long address;
    private final int size;
    final boolean thumb;
    CodeHistory(long address, int size, boolean thumb) {
        this.address = address;
        this.size = size;
        this.thumb = thumb;
    }

    Instruction disassemble(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        byte[] code = backend.mem_read(address, size);
        Instruction[] insns = emulator.disassemble(address, code, thumb, 1);
        if (insns.length == 0) {
            return null;
        } else {
            return insns[0];
        }
    }

}
