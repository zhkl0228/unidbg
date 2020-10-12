package com.github.unidbg.arm.backend;

import com.github.unidbg.arm.backend.dynarmic.DynarmicLoader;
import junit.framework.TestCase;
import unicorn.Arm64Const;

public class DynarmicBackendTest extends TestCase {

    static {
        DynarmicLoader.useDynarmic();
    }

    public void testInitialize() {
        Backend backend = DynarmicBackend.tryInitialize(null, true);
        assertNotNull(backend);
        backend.mem_map(0xffffe0000L, 0x10000, 0b101);
        backend.mem_map(0xbffe0000L, 0x20000, 0b11);
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, 0xc0000000L);
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, 0xbffffc00L);
        backend.destroy();

        backend = DynarmicBackend.tryInitialize(null, false);
        assertNotNull(backend);
        backend.destroy();
    }

}
