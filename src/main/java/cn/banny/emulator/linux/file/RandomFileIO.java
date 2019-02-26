package cn.banny.emulator.linux.file;

import cn.banny.emulator.Emulator;
import com.sun.jna.Pointer;
import unicorn.Unicorn;

import java.util.Random;

public class RandomFileIO extends DriverFileIO {

    private final Random random = new Random();

    RandomFileIO(String path) {
        super(O_RDONLY, path);
    }

    @Override
    public int read(Unicorn unicorn, Pointer buffer, int count) {
        byte[] data = new byte[count];
        random.nextBytes(data);
        buffer.write(0, data, 0, data.length);
        return data.length;
    }

    @Override
    public int fstat(Emulator emulator, Unicorn unicorn, Pointer stat) {
        return 0;
    }
}
