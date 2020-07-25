package com.github.unidbg.android.struct;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;

public class StatFSTest extends TestCase {

    public void testStatFS() throws Exception {
        byte[] data = Hex.decodeHex("53ef000000100000af3532000000000063572b000000000063572b0000000000b0cc0c00000000002ebd0c0000000000e89f60d36b0d9704ff0000000010000026040000000000000000000000000000000000007569643d".toCharArray());
        Inspector.inspect(data, "StatFS32");
    }

}
