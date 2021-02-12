package com.github.unidbg.arm.backend.kvm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Closeable;

public class Kvm implements Closeable {

    private static final Log log = LogFactory.getLog(Kvm.class);

    private static native int setKvmCallback(long handle, KvmCallback callback);

    public static native int getMaxSlots();
    public static native int getPageSize();
    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private static native long set_user_memory_region(long handle, int slot, long guest_phys_addr, long memory_size);

    private static native long reg_read_cpacr_el1(long handle);
    private static native int reg_set_cpacr_el1(long handle, long value);

    private static native int reg_set_sp64(long handle, long value);
    private static native long reg_read_sp64(long handle);
    private static native int reg_set_tpidr_el0(long handle, long value);
    private static native long reg_read_pc64(long handle);

    private static native int mem_write(long handle, long address, byte[] bytes);
    private static native byte[] mem_read(long handle, long address, int size);

    private static native int reg_write(long handle, int index, long value);
    private static native long reg_read(long handle, int index);

    private static native int emu_start(long handle, long pc);
    private static native int emu_stop(long handle);

    private final long nativeHandle;

    private static Kvm singleInstance;

    public Kvm(boolean is64Bit) {
        if (singleInstance != null) {
            throw new IllegalStateException("Only one kvm VM instance per process allowed.");
        }

        this.nativeHandle = nativeInitialize(is64Bit);
        singleInstance = this;
    }

    public void setKvmCallback(KvmCallback callback) {
        if (log.isDebugEnabled()) {
            log.debug("setKvmCallback callback" + callback);
        }

        int ret = setKvmCallback(nativeHandle, callback);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public long set_user_memory_region(int slot, long guest_phys_addr, long memory_size) {
        long userspace_addr = set_user_memory_region(nativeHandle, slot, guest_phys_addr, memory_size);
        if (userspace_addr == 0) {
            throw new KvmException("set_user_memory_region failed: slot=" + slot + ", guest_phys_addr=0x" + Long.toHexString(guest_phys_addr) + ", memory_size=0x" + Long.toHexString(memory_size));
        }
        return userspace_addr;
    }

    public long reg_read_cpacr_el1() {
        long cpacr = reg_read_cpacr_el1(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_cpacr_el1=0x" + Long.toHexString(cpacr));
        }
        return cpacr;
    }

    public void reg_set_cpacr_el1(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_cpacr_el1 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_cpacr_el1(nativeHandle, value);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public void reg_set_sp64(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_sp64 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_sp64(nativeHandle, value);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public long reg_read_sp64() {
        long sp = reg_read_sp64(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_sp64=0x" + Long.toHexString(sp));
        }
        return sp;
    }

    public long reg_read_pc64() {
        long pc = reg_read_pc64(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_pc64=0x" + Long.toHexString(pc));
        }
        return pc;
    }

    public void mem_write(long address, byte[] bytes) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_write(nativeHandle, address, bytes);
        if (log.isDebugEnabled()) {
            log.debug("mem_write address=0x" + Long.toHexString(address) + ", size=" + bytes.length + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public byte[] mem_read(long address, int size) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        byte[] ret = mem_read(nativeHandle, address, size);
        if (log.isDebugEnabled()) {
            log.debug("mem_read address=0x" + Long.toHexString(address) + ", size=" + size + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret == null) {
            throw new KvmException();
        }
        return ret;
    }

    public void reg_set_tpidr_el0(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_tpidr_el0 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_tpidr_el0(nativeHandle, value);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public void reg_write64(int index, long value) {
        if (index < 0 || index > 30) {
            throw new IllegalArgumentException("index=" + index);
        }
        if (log.isDebugEnabled()) {
            log.debug("reg_write64 index=" + index + ", value=0x" + Long.toHexString(value));
        }
        int ret = reg_write(nativeHandle, index, value);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public long reg_read64(int index) {
        if (index < 0 || index > 30) {
            throw new IllegalArgumentException("index=" + index);
        }
        if (log.isDebugEnabled()) {
            log.debug("reg_read64 index=" + index);
        }
        return reg_read(nativeHandle, index);
    }

    public void emu_start(long begin) {
        int ret = emu_start(nativeHandle, begin);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    public void emu_stop() {
        if (log.isDebugEnabled()) {
            log.debug("emu_stop");
        }

        int ret = emu_stop(nativeHandle);
        if (ret != 0) {
            throw new KvmException("ret=" + ret);
        }
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);

        singleInstance = null;
    }

}
