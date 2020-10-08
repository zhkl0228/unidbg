package com.github.unidbg.arm.backend.dynarmic;

import junit.framework.TestCase;
import unicorn.UnicornConst;

public class DynarmicTest extends TestCase {

    public void testInitialize() {
        try (Dynarmic dynarmic = new Dynarmic(true)) {
            assertTrue(dynarmic.nativeHandle > 0L);
            dynarmic.mem_map(0x0, 0x1000, UnicornConst.UC_PROT_WRITE);
        }
        try (Dynarmic dynarmic = new Dynarmic(false)) {
            assertTrue(dynarmic.nativeHandle > 0L);
            dynarmic.mem_map(0x2000, 0x1000 * 3, UnicornConst.UC_PROT_READ);
        }
    }

}
