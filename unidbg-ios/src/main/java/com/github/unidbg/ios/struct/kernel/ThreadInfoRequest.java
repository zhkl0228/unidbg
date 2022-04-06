package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ThreadInfoRequest extends UnidbgStructure {

    public ThreadInfoRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int flavor;
    public int infoCount; // THREAD_BASIC_INFO_COUNT

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "flavor", "infoCount");
    }

}
