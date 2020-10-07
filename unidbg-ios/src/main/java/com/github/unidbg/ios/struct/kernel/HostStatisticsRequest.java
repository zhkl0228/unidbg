package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostStatisticsRequest extends UnidbgStructure {

    public static final int HOST_VM_INFO = 2; /* Virtual memory stats */

    public HostStatisticsRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int flavor;
    public int count;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "flavor", "count");
    }

}
