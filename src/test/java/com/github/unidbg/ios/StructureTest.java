package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.ios.struct.kernel.Stat;
import com.github.unidbg.ios.struct.kernel.StatFS;
import com.github.unidbg.pointer.UnicornStructure;
import junit.framework.TestCase;

public class StructureTest extends TestCase {

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        AbstractEmulator.POINTER_SIZE.set(4);
    }

    public void testStat() {
        assertEquals(96, UnicornStructure.calculateSize(Stat.class));
    }

    public void testStatFS() {
        assertEquals(2136, UnicornStructure.calculateSize(StatFS.class));
    }

}
