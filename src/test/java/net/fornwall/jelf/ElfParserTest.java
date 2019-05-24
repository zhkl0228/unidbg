package net.fornwall.jelf;

import com.diffblue.deeptestutils.Reflector;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import java.io.ByteArrayInputStream;
import java.io.IOException;

@RunWith(PowerMockRunner.class)
public class ElfParserTest {

    @PrepareForTest(ElfFile.class)
    @Test
    public void testByteSwap() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(new byte[]{1, 2});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(16777216, elfParser.byteSwap(1));
        Assert.assertEquals((short) 2560, elfParser.byteSwap((short) 10));
        Assert.assertEquals(7205759403792793600L, elfParser.byteSwap(100L));
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testReadUnsignedByte() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(new byte[]{1});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(1, elfParser.readUnsignedByte());
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testReadShort() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(new byte[]{1, 2});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(258, elfParser.readShort());
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testReadInt() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(16909060, elfParser.readInt());
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testReadLong() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(72623859790382856L, elfParser.readLong());
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testReadIntOrLong() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(72623859790382856L, elfParser.readIntOrLong());
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testUnsignedByte() {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        Assert.assertEquals(123, elfParser.unsignedByte(123));
    }

    @PrepareForTest(MemoizedObject.class)
    @Test
    public void testVirtualMemoryAddrToFileOffset() throws Exception {
        ElfFile elfFile = (ElfFile)
                Reflector.getInstance("net.fornwall.jelf.ElfFile");

        ElfSegment elfSegment = (ElfSegment)
                Reflector.getInstance("net.fornwall.jelf.ElfSegment");
        Reflector.setField(elfSegment, "mem_size", 4_611_685_010_250_924_278L);
        Reflector.setField(elfSegment, "virtual_address", 1_008_176_471_803L);
        Reflector.setField(elfSegment,
                "file_size", 9_223_371_028_678_312_157L);

        MemoizedObject memoizedObj = PowerMockito.mock(MemoizedObject.class);
        PowerMockito.when(memoizedObj.getValue()).thenReturn(elfSegment);

        MemoizedObject[] memoizedObjectArray = {memoizedObj};
        Reflector.setField(elfFile, "programHeaders", memoizedObjectArray);
        Reflector.setField(elfFile, "num_ph", (short) 1);
        ElfParser elfParser = new ElfParser(elfFile,null);

        long address = 4_611_686_018_427_396_056L;
        Assert.assertEquals(4611685010250924253L,
                elfParser.virtualMemoryAddrToFileOffset(address));
    }

    @PrepareForTest(ElfFile.class)
    @Test
    public void testRead() throws IOException {
        ElfFile elfFile = PowerMockito.mock(ElfFile.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0});
        ElfParser elfParser = new ElfParser(elfFile, byteArrayInputStream);

        byte[] output = new byte[3];
        Assert.assertEquals(3, elfParser.read(output));
        Assert.assertArrayEquals(new byte[]{1,2,3}, output);
    }
}
