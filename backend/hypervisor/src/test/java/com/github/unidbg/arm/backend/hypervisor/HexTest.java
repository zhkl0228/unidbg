package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class HexTest extends TestCase {

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex(IOUtils.toCharArray(Objects.requireNonNull(getClass().getResourceAsStream("/hex.txt")), StandardCharsets.UTF_8));
        Inspector.inspect(data, "data");
    }

}
