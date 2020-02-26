package com.github.unidbg.file.linux;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

public abstract class StatStructure extends UnicornStructure {

    public StatStructure(Pointer p) {
        super(p);
    }

    public long st_dev;
    public long st_ino;
    public long st_size;
    public long st_rdev;

}
