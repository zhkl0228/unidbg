package com.github.unidbg.arm.backend;

import junit.framework.TestCase;

public class DynarmicBackendTest extends TestCase {

    public void testInitialize() {
        Backend backend = DynarmicBackend.tryInitialize(true);
        assertNotNull(backend);
        backend.destroy();

        backend = DynarmicBackend.tryInitialize(false);
        assertNotNull(backend);
        backend.destroy();
    }

}
