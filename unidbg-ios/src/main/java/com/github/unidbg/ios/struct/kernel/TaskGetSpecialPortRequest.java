package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskGetSpecialPortRequest extends UnicornStructure {

    public TaskGetSpecialPortRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int which;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "which");
    }

}
