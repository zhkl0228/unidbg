package com.github.unidbg;

import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;

public class HexTest extends TestCase {

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex("37ff000026f40100084c00004687000025704001583e000094eb0200140000009d469901222d0b00d52f01000c0000002a020000a02c00009d0c0000".toCharArray());
        Inspector.inspect(data, "testHex");
    }

    public void testStream() throws Exception {
        File testFile = new File("target/streamTest.txt");
        new PrintStream(testFile).println(123);
        new PrintStream(testFile).println("abc");
        assertEquals("abc\n", FileUtils.readFileToString(testFile));

        new PrintStream(new FileOutputStream(testFile, true), false).println(123);
        assertEquals("abc\n123\n", FileUtils.readFileToString(testFile));
    }

}
