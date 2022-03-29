package com.github.unidbg.ios.struct.sysctl;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskVmInfo64 extends UnidbgStructure {

    public TaskVmInfo64(Pointer p) {
        super(p);
    }

    public TaskVmInfo64(byte[] data) {
        super(data);
    }

    public long virtual_size; /* virtual memory size (bytes) */
    public int region_count; /* number of memory regions */
    public int page_size;
    public long resident_size; /* resident memory size (bytes) */
    public long resident_size_peak; /* peak resident size (bytes) */

    public long device;
    public long device_peak;
    public long internal;
    public long internal_peak;
    public long external;
    public long external_peak;
    public long reusable;
    public long reusable_peak;
    public long purgeable_volatile_pmap;
    public long purgeable_volatile_resident;
    public long purgeable_volatile_virtual;
    public long compressed;
    public long compressed_peak;
    public long compressed_lifetime;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("virtual_size", "region_count", "page_size", "resident_size", "resident_size_peak",
                "device", "device_peak", "internal", "internal_peak", "external", "external_peak",
                "reusable", "reusable_peak", "purgeable_volatile_pmap", "purgeable_volatile_resident",
                "purgeable_volatile_virtual", "compressed", "compressed_peak", "compressed_lifetime");
    }
}
