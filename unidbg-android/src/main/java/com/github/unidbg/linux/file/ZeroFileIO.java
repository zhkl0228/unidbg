package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.sun.jna.Pointer;

public class ZeroFileIO extends DriverFileIO {

    public ZeroFileIO(Emulator<?> emulator, int oflags, String path) {
        super(emulator, oflags, path);
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        int total = 0;
        byte[] buf = new byte[Math.min(0x1000, count)];
        Pointer pointer = buffer;
        while (total < count) {
            int read = Math.min(buf.length, count - total);
            pointer.write(0, buf, 0, read);
            total += read;
            pointer = pointer.share(read);
        }
        return total;
    }

    @Override
    public int write(byte[] data) {
        return data.length;
    }

    @Override
    protected byte[] getMmapData(int offset, int length) {
        return new byte[length];
    }

}
