package net.fornwall.jelf;

import com.sun.jna.Pointer;

import java.nio.ByteBuffer;

public class PtLoadData {

    private final ByteBuffer buffer;

    PtLoadData(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    public void writeTo(final Pointer ptr) {
        Pointer pointer = ptr;
        byte[] buf = new byte[Math.min(0x1000, buffer.remaining())];
        while (buffer.hasRemaining()) {
            int write = Math.min(buf.length, buffer.remaining());
            buffer.get(buf, 0, write);
            pointer.write(0, buf, 0, write);
            pointer = pointer.share(write);
        }
    }

}
