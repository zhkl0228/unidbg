package com.github.unidbg.arm.backend.hypervisor;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

public class HexTest extends TestCase {

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex(IOUtils.toCharArray(getClass().getResourceAsStream("/hex.txt")));
        Inspector.inspect(data, "data");
    }

}
