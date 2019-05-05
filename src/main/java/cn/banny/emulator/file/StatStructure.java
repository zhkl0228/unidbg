package cn.banny.emulator.file;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

public abstract class StatStructure extends UnicornStructure {

    public StatStructure(Pointer p) {
        super(p);
    }

    public int st_dev;
    public int st_mode;
    public int st_ino;

    public int st_size;
    public int st_blksize;

}
