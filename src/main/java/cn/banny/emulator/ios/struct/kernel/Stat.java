package cn.banny.emulator.ios.struct.kernel;

import cn.banny.emulator.file.StatStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat extends StatStructure {

    public Stat(Pointer p) {
        super(p);
    }

    public int[] gap1 = new int[12];
    public int[] gap2 = new int[3];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_mode", "st_ino", "gap1", "st_size", "gap2", "st_blksize");
    }

}
