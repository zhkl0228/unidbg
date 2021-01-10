package com.github.unidbg.arm.backend.hypervisor;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

class ExclusiveMonitor {

    static ExclusiveMonitor createExclusiveMonitor(ThreadLocal<ExclusiveMonitor> threadLocal) {
        ExclusiveMonitor monitor = threadLocal.get();
        if (monitor == null) {
            monitor = new ExclusiveMonitor();
            threadLocal.set(monitor);
        }
        return monitor;
    }

    private final Map<Pointer, byte[]> memoryData = new HashMap<>();

    void loadAcquireExclusive(Pointer pointer, int size) {
        memoryData.put(pointer, pointer.getByteArray(0, size));
    }

    synchronized boolean storeExclusive(Pointer pointer, int size, boolean release) {
        byte[] read = release ? memoryData.remove(pointer) : memoryData.get(pointer);
        if (read == null) {
            return false;
        }
        if (read.length != size) {
            throw new IllegalStateException("length=" + read.length + ", size=" + size);
        }
        return Arrays.equals(read, pointer.getByteArray(0, size));
    }

}
