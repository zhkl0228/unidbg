package com.github.unidbg.arm.backend.dynarmic;

import junit.framework.TestCase;

public class DynarmicTest extends TestCase {

    public void testInitialize() {
        try (Dynarmic dynarmic = new Dynarmic(true)) {
            assertTrue(dynarmic.nativeHandle > 0L);
        }
        try (Dynarmic dynarmic = new Dynarmic(false)) {
            assertTrue(dynarmic.nativeHandle > 0L);
        }
    }

}
