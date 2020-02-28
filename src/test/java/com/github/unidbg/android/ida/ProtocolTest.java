package com.github.unidbg.android.ida;

import com.github.unidbg.debugger.ida.Utils;
import com.github.unidbg.utils.Inspector;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;

import java.nio.ByteBuffer;

public class ProtocolTest extends TestCase {

    public void testSingle() throws Exception {
        testSingle("0000003600028080c0008966c0008966ff4015400100012f73797374656d2f6c69622f6c6962737464632b2b2e736f00ff4015400100b001000001");
        testSingle("0000003500028080c0008966c0008966ff4014f00100012f73797374656d2f6c69622f6c69626c6f672e736f00ff4014f00100c0005001000001");
        testSingle("0000003700028080c0008966c0008966ff4014700100012f73797374656d2f6c69622f6c696278686f6f6b2e736f00ff4014700100c0008001000001");
        testSingle("0000003300028080c0008966c0008966ff4010b00100012f73797374656d2f6c69622f6c69626d2e736f00ff4010b00100c001b001000001");
        testSingle("0000003400028080c0008966c0008966ff4010700100012f73797374656d2f6c69622f6c6962646c2e736f00ff4010700100c0004001000001");
        testSingle("0000003300028080c0008966c0008966ff400ac00100012f73797374656d2f6c69622f6c6962632e736f00ff400ac00100c005b001000001");

        testSingle("00000041000201c0008966c0008966ff400cc11500012f73797374656d2f62696e2f616e64726f69645f7365727665725f372e3400ff4000000100c00a200100ff4000000100");
        testSingle("0000004200018400c0008966c0008966ff400cc11500012f73797374656d2f62696e2f616e64726f69645f7365727665725f372e3400ff4000000100c00a200100ff4000000100");
    }

    private void testSingle(String hex) throws Exception {
        byte[] data = Hex.decodeHex(hex.toCharArray());
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int packetSize = buffer.getInt();
        buffer.get(); // type

        data = new byte[packetSize];
        buffer.get(data);
        buffer = ByteBuffer.wrap(data);

        byte type = buffer.get();
        long magic = Utils.unpack_dd(buffer);
        long pid = Utils.unpack_dd(buffer);
        long tid = Utils.unpack_dd(buffer);
        long pc = Utils.unpack_dd(buffer);
        short s1 = buffer.getShort();
        String path = Utils.readCString(buffer);
        long base = Utils.unpack_dd(buffer);
        byte b1 = buffer.get();
        long size = Utils.unpack_dd(buffer);
        byte b2 = buffer.get();
        long test = Utils.unpack_dd(buffer);
        boolean dylib = buffer.get() == 1;
        data = new byte[buffer.remaining()];
        buffer.get(data);
        Inspector.inspect(data, "type=" + type + ", magic=" + magic + ", pid=" + pid + ", tid=" + tid +
                ", pc=0x" + Long.toHexString(pc) + ", s1=" + s1 + ", path=" + path +
                ", base=0x" + Long.toHexString(base) + ", b1=" + b1 + ", size=0x" + Long.toHexString(size) + ", b2=" + b2 + ", test=0x" + Long.toHexString(test) +
                ", dylib=" + dylib);
    }

    public void testLoads() throws Exception {
        byte[] data = Hex.decodeHex("000002580005100100ff4000000100c00a200100152f73797374656d2f62696e2f616e64726f69645f7365727665725f372e3400000100ff400a200100c000a00100162f73797374656d2f62696e2f616e64726f69645f7365727665725f372e3400000100ff400ac00100c004800100152f73797374656d2f6c69622f6c6962632e736f00000100ff400f400100c001300100162f73797374656d2f6c69622f6c6962632e736f00000100ff4010700100a00100152f73797374656d2f6c69622f6c6962646c2e736f00000100ff4010900100a00100162f73797374656d2f6c69622f6c6962646c2e736f00000100ff4010b00100c001800100152f73797374656d2f6c69622f6c69626d2e736f00000100ff4012400100a00100162f73797374656d2f6c69622f6c69626d2e736f00000100ff4014700100c000600100152f73797374656d2f6c69622f6c696278686f6f6b2e736f00000100ff4014d00100a00100162f73797374656d2f6c69622f6c696278686f6f6b2e736f00000100ff4014f00100b00100152f73797374656d2f6c69622f6c69626c6f672e736f00000100ff4015200100a00100162f73797374656d2f6c69622f6c69626c6f672e736f00000100ff4015400100900100152f73797374656d2f6c69622f6c6962737464632b2b2e736f00000100ff4015500100a00100162f73797374656d2f6c69622f6c6962737464632b2b2e736f00000100ff4015700100c001b00100152f73797374656d2f6c69622f6c6962686f6f6b7a7a2e736f00000100ff4017300100b00100162f73797374656d2f6c69622f6c6962686f6f6b7a7a2e736f0000".toCharArray());
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int packetSize = buffer.getInt();
        buffer.get(); // type

        data = new byte[packetSize];
        buffer.get(data);
        buffer = ByteBuffer.wrap(data);

        Utils.unpack_dd(buffer);
        long count = Utils.unpack_dd(buffer);
        for (int i = 0; i < count; i++) {
            int alignment = buffer.getShort() & 0xffff;
            long base = Utils.unpack_dd(buffer) & (-alignment);
            byte b1 = buffer.get();
            long size = Utils.unpack_dd(buffer) & (-alignment);
            int mask = buffer.getShort();
            String path = Utils.readCString(buffer);
            byte b2 = buffer.get();
            boolean d = ((mask >> 4) & 1) != 0;
            boolean r = ((mask >> 2) & 1) != 0;
            boolean w = ((mask >> 1) & 1) != 0;
            boolean x = ((mask) & 1) != 0;
            System.out.println("alignment=0x" + Integer.toHexString(alignment) + ", base=0x" + Long.toHexString(base) + ", b1=0x" + Integer.toHexString(b1) +
                    ", d=" + d + ", r=" + r + ", w=" + w + ", x=" + x +
                    ", size=0x" + Long.toHexString(size) +
                    ", mask=0x" + Integer.toHexString(mask) + ", path=" + path + ", b2=" + b2);
        }
    }

    public void testPackDD() {
        assertEquals("c0008a37", Hex.encodeHexString(Utils.pack_dd(0x8a37)));
    }

}
