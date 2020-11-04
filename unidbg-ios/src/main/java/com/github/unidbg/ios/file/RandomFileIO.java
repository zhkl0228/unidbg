package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.ios.IOConstants;
import com.sun.jna.Pointer;

public class RandomFileIO extends DriverFileIO {

    public RandomFileIO(Emulator<?> emulator, String path) {
        super(emulator, IOConstants.O_RDONLY, path);
    }

    @Override
    public int read(Backend backend, Pointer buffer, int count) {
        int total = 0;
        byte[] buf = new byte[Math.min(0x1000, count)];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) i;
        }
        Pointer pointer = buffer;
        while (total < count) {
            int read = Math.min(buf.length, count - total);
            pointer.write(0, buf, 0, read);
            total += read;
            pointer = pointer.share(read);
        }
        return total;
    }
}
