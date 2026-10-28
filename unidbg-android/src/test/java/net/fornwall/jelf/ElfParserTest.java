package net.fornwall.jelf;

import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;

public class ElfParserTest {

    @Test
    public void readsStayInsideBuffer() {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        ElfParser parser = new ElfParser(null, buffer);

        parser.seek(100);
        assertEquals(16, buffer.position());
        assertEquals(0, parser.readUnsignedByte());

        parser.seek(-1);
        assertEquals(0, buffer.position());

        parser.seek(10);
        ByteBuffer slice = parser.readBuffer(100);
        assertEquals(6, slice.remaining());
    }

}
