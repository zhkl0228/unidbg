package com.github.unidbg.arm.backend;

import junit.framework.TestCase;

public class Arm64Test extends TestCase {

    public void testSys() {
        int code = 0xD50B7522;
        System.out.println("0x" + Integer.toHexString(code >>> 19));
    }

}
