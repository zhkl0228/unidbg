package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractEmulator;
import cn.banny.emulator.ios.struct.kernel.Stat;
import cn.banny.emulator.ios.struct.kernel.StatFS;
import cn.banny.emulator.pointer.UnicornStructure;
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
