package com.github.unidbg.linux.file;

import com.github.unidbg.Emulator;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

public class ZeroFileIO extends DriverFileIO {

    public ZeroFileIO(Emulator<?> emulator, int oflags, String path) {
        super(emulator, oflags, path);
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        buffer.write(0, new byte[count], 0, count);
        return count;
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
