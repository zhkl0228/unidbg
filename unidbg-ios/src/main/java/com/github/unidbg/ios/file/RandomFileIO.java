package com.github.unidbg.ios.file;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.ios.IOConstants;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

public class RandomFileIO extends DriverFileIO {

    public RandomFileIO(Emulator<?> emulator, String path) {
        super(emulator, IOConstants.O_RDONLY, path);
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        byte[] data = new byte[count];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        buffer.write(0, data, 0, data.length);
        return data.length;
    }
}
