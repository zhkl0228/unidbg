package com.github.unidbg.arm.backend.hypervisor;

import com.sun.jna.Pointer;
import junit.framework.TestCase;
import org.scijava.nativelib.NativeLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class VCpuTest extends TestCase {

    private static final Logger log = LoggerFactory.getLogger(VCpuTest.class);

    static {
        try {
            NativeLoader.loadLibrary("hypervisor");
        } catch (IOException ignored) {
        }
    }

    public void testVcpu() throws Exception {
        Pointer vcpu = Hypervisor.getVCpusPointer();
        assertNotNull(vcpu);
        System.out.println(vcpu);

        try (final Hypervisor hypervisor = new Hypervisor(true)) {
            {
                Pointer context = hypervisor.getCpuContextPointer();
                assertNotNull(context);
                Pointer cpu = hypervisor.lookupVcpuPointer();
                log.info("main context={}, cpu={}", context, cpu);
            }

            Thread thread = new Thread(() -> {
                Pointer context = hypervisor.getCpuContextPointer();
                assertNotNull(context);
                Pointer cpu = hypervisor.lookupVcpuPointer();
                log.info("thread context={}, cpu={}", context, cpu);
            }, "TestThread");
            thread.start();
            thread.join();
        }

    }

}
