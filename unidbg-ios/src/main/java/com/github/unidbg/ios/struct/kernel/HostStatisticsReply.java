package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.ios.struct.VMStatistics;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostStatisticsReply extends UnidbgStructure {

    public HostStatisticsReply(Pointer p, int size) {
        super(p);
        this.data = new byte[size];
    }

    public NDR_record NDR;
    public int retCode;
    public int host_info_outCnt;
    public byte[] data;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "retCode", "host_info_outCnt", "data");
    }

    public void writeVMStatistics() {
        VMStatistics vmStatistics = new VMStatistics(getPointer().share(fieldOffset("data")));
        vmStatistics.free_count = 0xff37;
        vmStatistics.active_count = 0x1f426;
        vmStatistics.inactive_count = 0x4c08;
        vmStatistics.wire_count = 0x8746;
        vmStatistics.zero_fill_count = 0x1407025;
        vmStatistics.reactivations = 0x3e58;
        vmStatistics.pageins = 0x2eb94;
        vmStatistics.pageouts = 0x14;
        vmStatistics.faults = 0x199469d;
        vmStatistics.cow_faults = 0xb2d22;
        vmStatistics.lookups = 0x12fd5;
        vmStatistics.hits = 0xc;
        vmStatistics.purgeable_count = 0x22a;
        vmStatistics.purges = 0x2ca0;
        vmStatistics.speculative_count = 0xc9d;
        vmStatistics.pack();
        this.unpack();
    }
}
