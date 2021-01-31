package com.github.unidbg.arm.backend.dynarmic;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.Closeable;

public class Dynarmic implements Closeable {

    private static final Log log = LogFactory.getLog(Dynarmic.class);

    private static native int setDynarmicCallback(long handle, DynarmicCallback callback);

    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private static native int mem_unmap(long handle, long address, long size);
    private static native int mem_map(long handle, long address, long size, int perms);
    private static native int mem_protect(long handle, long address, long size, int perms);

    private static native int mem_write(long handle, long address, byte[] bytes);
    private static native byte[] mem_read(long handle, long address, int size);

    private static native long reg_read_pc64(long handle);
    private static native int reg_set_sp64(long handle, long value);
    private static native long reg_read_sp64(long handle);
    private static native long reg_read_nzcv(long handle);
    private static native int reg_set_nzcv(long handle, long value);
    private static native int reg_set_tpidr_el0(long handle, long value);
    private static native int reg_set_tpidrro_el0(long handle, long value);
    private static native int reg_set_vector(long handle, int index, byte[] vector);

    private static native int reg_write(long handle, int index, long value);
    private static native long reg_read(long handle, int index);
    private static native int reg_read_cpsr(long handle);
    private static native int reg_write_cpsr(long handle, int value);
    private static native int reg_write_c13_c0_3(long handle, int value);

    private static native int emu_start(long handle, long pc);
    private static native int emu_stop(long handle);

    private final long nativeHandle;

    public Dynarmic(boolean is64Bit) {
        this.nativeHandle = nativeInitialize(is64Bit);
    }

    public void setDynarmicCallback(DynarmicCallback callback) {
        if (log.isDebugEnabled()) {
            log.debug("setDynarmicCallback callback" + callback);
        }

        int ret = setDynarmicCallback(nativeHandle, callback);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void emu_start(long begin) {
        int ret = emu_start(nativeHandle, begin);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void emu_stop() {
        if (log.isDebugEnabled()) {
            log.debug("emu_stop");
        }

        int ret = emu_stop(nativeHandle);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void mem_unmap(long address, long size) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_unmap(nativeHandle, address, size);
        if (log.isDebugEnabled()) {
            log.debug("mem_unmap address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void mem_map(long address, long size, int perms) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_map(nativeHandle, address, size, perms);
        if (log.isDebugEnabled()) {
            log.debug("mem_map address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", perms=0b" + Integer.toBinaryString(perms) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void mem_protect(long address, long size, int perms) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_protect(nativeHandle, address, size, perms);
        if (log.isDebugEnabled()) {
            log.debug("mem_protect address=0x" + Long.toHexString(address) + ", size=0x" + Long.toHexString(size) + ", perms=0b" + Integer.toBinaryString(perms) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_set_sp64(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_sp64 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_sp64(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public long reg_read_pc64() {
        long pc = reg_read_pc64(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_pc64=0x" + Long.toHexString(pc));
        }
        return pc;
    }

    public long reg_read_sp64() {
        long sp = reg_read_sp64(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_sp64=0x" + Long.toHexString(sp));
        }
        return sp;
    }

    public long reg_read_nzcv() {
        long nzcv = reg_read_nzcv(nativeHandle);
        if (log.isDebugEnabled()) {
            log.debug("reg_read_nzcv=0x" + Long.toHexString(nzcv));
        }
        return nzcv;
    }

    public void reg_set_nzcv(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_nzcv value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_nzcv(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_set_tpidr_el0(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_tpidr_el0 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_tpidr_el0(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_set_tpidrro_el0(long value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_set_tpidrro_el0 value=0x" + Long.toHexString(value));
        }
        int ret = reg_set_tpidrro_el0(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_set_vector(int index, byte[] vector) {
        int ret = reg_set_vector(nativeHandle, index, vector);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_write32(int index, long value) {
        if (index < 0 || index > 15) {
            throw new IllegalArgumentException("index=" + index);
        }
        value &= 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("reg_write32 index=" + index + ", value=0x" + Long.toHexString(value));
        }
        int ret = reg_write(nativeHandle, index, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public void reg_write_c13_c0_3(int value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_write_c13_c0_3 value=0x" + Long.toHexString(value));
        }
        int ret = reg_write_c13_c0_3(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
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
            throw new DynarmicException("ret=" + ret);
        }
    }

    public int reg_read32(int index) {
        if (index < 0 || index > 15) {
            throw new IllegalArgumentException("index=" + index);
        }
        if (log.isDebugEnabled()) {
            log.debug("reg_read32 index=" + index);
        }
        return (int) (reg_read(nativeHandle, index) & 0xffffffffL);
    }

    public int reg_read_cpsr() {
        if (log.isDebugEnabled()) {
            log.debug("reg_read_cpsr");
        }
        return reg_read_cpsr(nativeHandle);
    }

    public void reg_write_cpsr(int value) {
        if (log.isDebugEnabled()) {
            log.debug("reg_write_cpsr value=0x" + Integer.toHexString(value));
        }
        int ret = reg_write_cpsr(nativeHandle, value);
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
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

    public void mem_write(long address, byte[] bytes) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_write(nativeHandle, address, bytes);
        if (log.isDebugEnabled()) {
            log.debug("mem_write address=0x" + Long.toHexString(address) + ", size=" + bytes.length + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret != 0) {
            throw new DynarmicException("ret=" + ret);
        }
    }

    public byte[] mem_read(long address, int size) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        byte[] ret = mem_read(nativeHandle, address, size);
        if (log.isDebugEnabled()) {
            log.debug("mem_read address=0x" + Long.toHexString(address) + ", size=" + size + ", offset=" + (System.currentTimeMillis() - start) + "ms");
        }
        if (ret == null) {
            throw new DynarmicException();
        }
        return ret;
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);
    }

}
