package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostInfo extends UnidbgStructure {

    public HostInfo(Pointer p) {
        super(p);
    }

    public int kernel_priority;
    public int system_priority;
    public int server_priority;
    public int user_priority;
    public int depress_priority;
    public int idle_priority;
    public int minimum_priority;
    public int maximum_priority;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("kernel_priority", "system_priority", "server_priority", "user_priority", "depress_priority", "idle_priority", "minimum_priority", "maximum_priority");
    }
}
