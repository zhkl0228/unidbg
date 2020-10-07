package com.github.unidbg.linux.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SysInfo32 extends UnidbgStructure {

    public SysInfo32(Pointer p) {
        super(p);
    }

    public int uptime;
    public int[] loads = new int[3];
    public int totalRam;
    public int freeRam;
    public int sharedRam;
    public int bufferRam;
    public int totalSwap;
    public int freeSwap;
    public short procs;
    public short pad;
    public int totalHigh;
    public int freeHigh;
    public int mem_unit;
    public byte[] _f = new byte[8];

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("uptime", "loads", "totalRam", "freeRam", "sharedRam", "bufferRam", "totalSwap", "freeSwap", "procs", "pad", "totalHigh", "freeHigh", "mem_unit", "_f");
    }
}
