package cn.banny.unidbg.ios;

import cn.banny.unidbg.AbstractEmulator;
import cn.banny.unidbg.ios.struct.kernel.Stat;
import cn.banny.unidbg.ios.struct.kernel.StatFS;
import cn.banny.unidbg.pointer.UnicornStructure;
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
