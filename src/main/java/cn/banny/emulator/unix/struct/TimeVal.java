package cn.banny.emulator.unix.struct;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TimeVal extends UnicornStructure {

    public TimeVal(Pointer p) {
        super(p);
    }

    public int tv_sec;
    public int tv_usec;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("tv_sec", "tv_usec");
    }

}
