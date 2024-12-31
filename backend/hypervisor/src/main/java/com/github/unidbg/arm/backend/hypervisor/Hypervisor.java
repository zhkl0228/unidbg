package com.github.unidbg.arm.backend.hypervisor;

import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;

public class Hypervisor implements Closeable {

    private static final Logger log = LoggerFactory.getLogger(Hypervisor.class);

    public static native void testVcpu();

    public static final long REG_VBAR_EL1 = 0xf0000000L;
    public static final long PSTATE$SS = 1 << 21;

    public static native int getPageSize();

    private static native int setHypervisorCallback(long handle, HypervisorCallback callback);

    private static native long nativeInitialize(boolean is64Bit);
    private static native void nativeDestroy(long handle);

    private static native int mem_unmap(long handle, long address, long size);
    private static native int mem_map(long handle, long address, long size, int perms);
    private static native int mem_protect(long handle, long address, long size, int perms);

    private static native int reg_write(long handle, int index, long value);
    private static native int reg_set_sp64(long handle, long value);
    private static native int reg_set_tpidr_el0(long handle, long value);
    private static native int reg_set_tpidrro_el0(long handle, long value);
    private static native int reg_set_nzcv(long handle, long value);
    private static native int reg_set_cpacr_el1(long handle, long value);
    private static native int reg_set_elr_el1(long handle, long value);
    private static native byte[] reg_read_vector(long handle, int index);
    private static native int reg_set_vector(long handle, int index, byte[] vector);
    private static native int reg_set_spsr_el1(long handle, long value);

    private static native int mem_write(long handle, long address, byte[] bytes);
    private static native byte[] mem_read(long handle, long address, int size);

    private static native long reg_read(long handle, int index);
    private static native long reg_read_sp64(long handle);
    private static native long reg_read_pc64(long handle);
    private static native long reg_read_nzcv(long handle);
    private static native long reg_read_cpacr_el1(long handle);

    private static native int emu_start(long handle, long pc);
    private static native int emu_stop(long handle);

    public static native long context_alloc();
    private static native void context_save(long handle, long context);
    private static native void context_restore(long handle, long context);
    public static native void free(long context);

    private static native int getBRPs(long handle);
    private static native int getWRPs(long handle);

    private static native long getCpuContext(long handle); // _hv_vcpu_get_context
    private static native long lookupVcpu(long handle);
    private static native long getVCpus(); // find_vcpus

    public final Pointer getCpuContextPointer() {
        long peer = getCpuContext(nativeHandle);
        return peer == 0L ? Pointer.NULL : new Pointer(peer);
    }
    public final Pointer lookupVcpuPointer() {
        long peer = lookupVcpu(nativeHandle);
        return peer == 0L ? Pointer.NULL : new Pointer(peer);
    }
    public static Pointer getVCpusPointer() {
        long peer = getVCpus();
        return peer == 0 ? Pointer.NULL : new Pointer(peer);
    }

    public int getBRPs() {
        return getBRPs(nativeHandle);
    }
    public int getWRPs() {
        return getWRPs(nativeHandle);
    }

    private static native void enable_single_step(long handle, boolean status);
    public void enable_single_step(boolean status) {
        if (log.isDebugEnabled()) {
            log.debug("enable_single_step status={}", status);
        }
        enable_single_step(nativeHandle, status);
    }

    public void install_hw_breakpoint(int n, long address) {
        if (log.isDebugEnabled()) {
            log.debug("install_hw_breakpoint n={}, address=0x{}", n, Long.toHexString(address));
        }
        install_hw_breakpoint(nativeHandle, n, address);
    }
    private static native void install_hw_breakpoint(long handle, int n, long address);
    public void disable_hw_breakpoint(int n) {
        if (log.isDebugEnabled()) {
            log.debug("disable_hw_breakpoint n={}", n);
        }
        disable_hw_breakpoint(nativeHandle, n);
    }
    private static native void disable_hw_breakpoint(long handle, int n);

    public void install_watchpoint(int n, long dbgwvr, long dbgwcr) {
        install_watchpoint(nativeHandle, n, dbgwcr, dbgwvr);
        if (log.isDebugEnabled()) {
            log.debug("install_watchpoint n={}, dbgwvr=0x{}, dbgwcr=0x{}", n, Long.toHexString(dbgwvr), Long.toHexString(dbgwcr));
        }
    }
    public void disable_watchpoint(int n) {
        install_watchpoint(nativeHandle, n, 0, 0);
        if (log.isDebugEnabled()) {
            log.debug("disable_watchpoint n={}", n);
        }
    }
    private static native void install_watchpoint(long handle, int n, long dbgwcr, long dbgwvr);

    private final long nativeHandle;

    private static Hypervisor singleInstance;

    public Hypervisor(boolean is64Bit) {
        if (!is64Bit) {
            throw new UnsupportedOperationException();
        }

        if (singleInstance != null) {
            throw new IllegalStateException("Only one hypervisor VM instance per process allowed.");
        }

        this.nativeHandle = nativeInitialize(is64Bit);
        singleInstance = this;
    }

    public void context_save(long context) {
        context_save(nativeHandle, context);
    }

    public void context_restore(long context) {
        context_restore(nativeHandle, context);
    }

    public void setHypervisorCallback(HypervisorCallback callback) {
        if (log.isTraceEnabled()) {
            log.trace("setHypervisorCallback callback={}", callback);
        }

        int ret = setHypervisorCallback(nativeHandle, callback);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void mem_map(long address, long size, int perms) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_map(nativeHandle, address, size, perms);
        if (log.isTraceEnabled()) {
            log.trace("mem_map address=0x{}, size=0x{}, perms=0b{}, offset={}ms", Long.toHexString(address), Long.toHexString(size), Integer.toBinaryString(perms), System.currentTimeMillis() - start);
        }
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void mem_protect(long address, long size, int perms) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_protect(nativeHandle, address, size, perms);
        if (log.isTraceEnabled()) {
            log.trace("mem_protect address=0x{}, size=0x{}, perms=0b{}, offset={}ms", Long.toHexString(address), Long.toHexString(size), Integer.toBinaryString(perms), System.currentTimeMillis() - start);
        }
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void mem_unmap(long address, long size) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_unmap(nativeHandle, address, size);
        if (log.isTraceEnabled()) {
            log.trace("mem_unmap address=0x{}, size=0x{}, offset={}ms", Long.toHexString(address), Long.toHexString(size), System.currentTimeMillis() - start);
        }
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_write64(int index, long value) {
        if (index < 0 || index > 30) {
            throw new IllegalArgumentException("index=" + index);
        }
        if (log.isTraceEnabled()) {
            log.trace("reg_write64 index={}, value=0x{}", index, Long.toHexString(value));
        }
        int ret = reg_write(nativeHandle, index, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_sp64(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_sp64 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_sp64(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_tpidr_el0(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_tpidr_el0 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_tpidr_el0(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_tpidrro_el0(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_tpidrro_el0 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_tpidrro_el0(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_nzcv(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_nzcv value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_nzcv(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_cpacr_el1(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_cpacr_el1 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_cpacr_el1(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_elr_el1(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_elr_el1 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_elr_el1(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public byte[] reg_read_vector(int index) {
        byte[] ret = reg_read_vector(nativeHandle, index);
        if (ret == null) {
            throw new HypervisorException();
        } else {
            return ret;
        }
    }

    public void reg_set_vector(int index, byte[] vector) {
        int ret = reg_set_vector(nativeHandle, index, vector);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void reg_set_spsr_el1(long value) {
        if (log.isTraceEnabled()) {
            log.trace("reg_set_spsr_el1 value=0x{}", Long.toHexString(value));
        }
        int ret = reg_set_spsr_el1(nativeHandle, value);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void mem_write(long address, byte[] bytes) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        int ret = mem_write(nativeHandle, address, bytes);
        if (log.isTraceEnabled()) {
            log.trace("mem_write address=0x{}, size={}, offset={}ms", Long.toHexString(address), bytes.length, System.currentTimeMillis() - start);
        }
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public byte[] mem_read(long address, int size) {
        long start = log.isDebugEnabled() ? System.currentTimeMillis() : 0;
        byte[] ret = mem_read(nativeHandle, address, size);
        if (log.isTraceEnabled()) {
            log.trace("mem_read address=0x{}, size={}, offset={}ms", Long.toHexString(address), size, System.currentTimeMillis() - start);
        }
        if (ret == null) {
            throw new HypervisorException();
        }
        return ret;
    }

    public long reg_read64(int index) {
        if (index < 0 || index > 30) {
            throw new IllegalArgumentException("index=" + index);
        }
        if (log.isTraceEnabled()) {
            log.trace("reg_read64 index={}", index);
        }
        return reg_read(nativeHandle, index);
    }

    public long reg_read_sp64() {
        long sp = reg_read_sp64(nativeHandle);
        if (log.isTraceEnabled()) {
            log.trace("reg_read_sp64=0x{}", Long.toHexString(sp));
        }
        return sp;
    }

    public long reg_read_pc64() {
        long pc = reg_read_pc64(nativeHandle);
        if (log.isTraceEnabled()) {
            log.trace("reg_read_pc64=0x{}", Long.toHexString(pc));
        }
        return pc;
    }

    public long reg_read_nzcv() {
        long nzcv = reg_read_nzcv(nativeHandle);
        if (log.isTraceEnabled()) {
            log.trace("reg_read_nzcv=0x{}", Long.toHexString(nzcv));
        }
        return nzcv;
    }

    public long reg_read_cpacr_el1() {
        long cpacr = reg_read_cpacr_el1(nativeHandle);
        if (log.isTraceEnabled()) {
            log.trace("reg_read_cpacr_el1=0x{}", Long.toHexString(cpacr));
        }
        return cpacr;
    }

    public void emu_start(long begin) {
        int ret = emu_start(nativeHandle, begin);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    public void emu_stop() {
        if (log.isTraceEnabled()) {
            log.trace("emu_stop");
        }

        int ret = emu_stop(nativeHandle);
        if (ret != 0) {
            throw new HypervisorException("ret=" + ret);
        }
    }

    @Override
    public void close() {
        nativeDestroy(nativeHandle);

        singleInstance = null;
    }

}
