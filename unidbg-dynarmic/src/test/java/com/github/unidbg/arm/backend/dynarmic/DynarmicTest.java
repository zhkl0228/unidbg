package com.github.unidbg.arm.backend.dynarmic;

import junit.framework.TestCase;
import unicorn.UnicornConst;

public class DynarmicTest extends TestCase {

    static {
        DynarmicLoader.useDynarmic();
    }

    public void testInitialize() {
        try (Dynarmic dynarmic = new Dynarmic(true)) {
            dynarmic.mem_map(0x0, 0x1000, UnicornConst.UC_PROT_WRITE);
            dynarmic.mem_protect(0x0, 0x1000, UnicornConst.UC_PROT_READ);
            dynarmic.mem_unmap(0x0, 0x1000);
        }
        try (Dynarmic dynarmic = new Dynarmic(false)) {
            dynarmic.mem_map(0x2000, 0x1000 * 3, UnicornConst.UC_PROT_READ);
            dynarmic.mem_unmap(0x2000, 0x1000 * 2);
            dynarmic.mem_protect(0x4000, 0x1000, UnicornConst.UC_PROT_WRITE);
        }
    }

}
