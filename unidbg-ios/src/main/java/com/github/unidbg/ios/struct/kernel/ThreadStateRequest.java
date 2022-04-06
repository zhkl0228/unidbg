package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ThreadStateRequest extends UnidbgStructure {

    public static final int ARM_THREAD_STATE = 1;
    public static final int ARM_THREAD_STATE64 = 6;

    public static final int ARM_THREAD_STATE_COUNT = 17;
    public static final int ARM_THREAD_STATE64_COUNT = 68;

    public ThreadStateRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int flavor;
    public int stateCount; // ARM_THREAD_STATE_COUNT or ARM_THREAD_STATE64_COUNT

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "flavor", "stateCount");
    }

}
