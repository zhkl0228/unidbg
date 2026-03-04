package com.github.unidbg.memory;

public class AllocationRecord {

    public final long address;
    public final long size;
    public final int perms;
    public final String[] guestBacktrace;
    public final StackTraceElement[] hostStackTrace;
    public final long timestamp;

    AllocationRecord(long address, long size, int perms,
                     String[] guestBacktrace, StackTraceElement[] hostStackTrace) {
        this.address = address;
        this.size = size;
        this.perms = perms;
        this.guestBacktrace = guestBacktrace;
        this.hostStackTrace = hostStackTrace;
        this.timestamp = System.nanoTime();
    }

    @Override
    public String toString() {
        return "AllocationRecord{address=0x" + Long.toHexString(address) +
                ", size=0x" + Long.toHexString(size) +
                ", perms=" + perms + '}';
    }

}
