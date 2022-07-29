package com.github.unidbg;

import capstone.api.Disassembler;
import capstone.api.DisassemblerFactory;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HexTest extends TestCase {

    public void testHex() throws Exception {
        byte[] data = Hex.decodeHex("37ff000026f40100084c00004687000025704001583e000094eb0200140000009d469901222d0b00d52f01000c0000002a020000a02c00009d0c0000".toCharArray());
        Inspector.inspect(data, "testHex");

        StringBuilder builder = new StringBuilder();
        ARM.appendHex(builder, 8, 8, '0', false);
        assertEquals(String.format("0x%08x", 8), builder.toString());
    }

    public void testDisassembler() throws Exception {
        try (Disassembler disassembler = DisassemblerFactory.createArm64Disassembler()) {
            disassembler.setDetail(true);
            byte[] code = Hex.decodeHex("017544bd".toCharArray());
            Instruction instruction = disassembler.disasm(code, 0)[0];
            assertNotNull(instruction);
            RegsAccess regsAccess = instruction.regsAccess();
            assertNotNull(regsAccess);
            System.out.println("regsRead=" + Arrays.toString(regsAccess.getRegsRead()));
            System.out.println("regsWrite=" + Arrays.toString(regsAccess.getRegsWrite()));
        }
    }

    public void testStream() throws Exception {
        File testFile = new File("target/streamTest.txt");
        new PrintStream(testFile).println(123);
        new PrintStream(testFile).println("abc");
        assertEquals("abc\n", FileUtils.readFileToString(testFile, StandardCharsets.UTF_8));

        new PrintStream(new FileOutputStream(testFile, true), false).println(123);
        assertEquals("abc\n123\n", FileUtils.readFileToString(testFile, StandardCharsets.UTF_8));
    }

    public void testFormat() {
        byte[] code = new byte[2];
        assertEquals("    0000", String.format("%8s", Hex.encodeHexString(code)));
        assertEquals("00000000", String.format("%8s", Hex.encodeHexString(new byte[4])));
    }

}
