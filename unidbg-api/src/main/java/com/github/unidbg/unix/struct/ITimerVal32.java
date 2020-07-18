package com.github.unidbg.unix.struct;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ITimerVal32 extends UnicornStructure {

    public ITimerVal32(Pointer p) {
        super(p);
    }

    public TimeVal32 it_interval; /* timer interval */
    public TimeVal32 it_value; /* current value */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("it_interval", "it_value");
    }
}
