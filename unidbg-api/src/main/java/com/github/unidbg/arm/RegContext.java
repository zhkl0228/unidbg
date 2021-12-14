package com.github.unidbg.arm;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;

import java.util.HashMap;
import java.util.Map;

class RegContext {

    static RegContext backupContext(Emulator<?> emulator, int... regs) {
        Map<Integer, UnidbgPointer> ctx = new HashMap<>();
        for (int reg : regs) {
            ctx.put(reg, UnidbgPointer.register(emulator, reg));
        }
        return new RegContext(emulator.getBackend(), ctx);
    }

    private final Backend backend;
    private final Map<Integer, UnidbgPointer> ctx;

    private RegContext(Backend backend, Map<Integer, UnidbgPointer> ctx) {
        this.backend = backend;
        this.ctx = ctx;
    }

    void restore() {
        for (Map.Entry<Integer, UnidbgPointer> entry : ctx.entrySet()) {
            UnidbgPointer ptr = entry.getValue();
            backend.reg_write(entry.getKey(), ptr == null ? 0 : ptr.peer);
        }
    }

}
