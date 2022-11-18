package com.github.unidbg.arm;

import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;

public class CodeHistory {

    public final long address;
    private final int size;
    final boolean thumb;
    CodeHistory(long address, int size, boolean thumb) {
        this.address = address;
        this.size = size;
        this.thumb = thumb;
    }

    Instruction[] disassemble(Emulator<?> emulator) {
        if (size <= 1) {
            return null;
        }
        Backend backend = emulator.getBackend();
        try {
            byte[] code = backend.mem_read(address, size);
            return emulator.disassemble(address, code, thumb, 0);
        } catch(BackendException e) {
            return null;
        }
    }

}
