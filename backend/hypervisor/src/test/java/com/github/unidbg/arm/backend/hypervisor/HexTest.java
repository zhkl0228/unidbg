package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.scijava.nativelib.NativeLoader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class HexTest extends TestCase {

    static {
        try {
            NativeLoader.loadLibrary("hypervisor");
        } catch (IOException ignored) {
        }
    }

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex(IOUtils.toCharArray(Objects.requireNonNull(getClass().getResourceAsStream("/hex.txt")), StandardCharsets.UTF_8));
        Inspector.inspect(data, "data");
    }

    public void testVcpu() throws Exception {
        Hypervisor.testVcpu();
        Thread thread = new Thread(Hypervisor::testVcpu);
        thread.start();
        thread.join();
    }

}
