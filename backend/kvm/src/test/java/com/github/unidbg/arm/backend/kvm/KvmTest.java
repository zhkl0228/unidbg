package com.github.unidbg.arm.backend.kvm;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.KvmFactory;
import junit.framework.TestCase;

import java.util.Collections;

public class KvmTest extends TestCase {

    public void testBackend() {
        Backend backend = BackendFactory.createBackend(null, true, Collections.<BackendFactory>singleton(new KvmFactory(false)));
        assertNotNull(backend);
        backend.destroy();
    }

}
