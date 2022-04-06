package com.github.unidbg.arm.backend;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.hypervisor.Hypervisor;
import com.github.unidbg.arm.backend.hypervisor.HypervisorCallback;
import com.github.unidbg.arm.backend.hypervisor.HypervisorException;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class HypervisorBackend extends FastBackend implements Backend, HypervisorCallback {

    private static final Log log = LogFactory.getLog(HypervisorBackend.class);

    protected final Hypervisor hypervisor;
    private final int pageSize;

    protected HypervisorBackend(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator);
        this.hypervisor = hypervisor;
        this.pageSize = Hypervisor.getPageSize();
        try {
            this.hypervisor.setHypervisorCallback(this);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void onInitialize() {
        super.onInitialize();

        mem_map(Hypervisor.REG_VBAR_EL1, getPageSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        ByteBuffer buffer = ByteBuffer.allocate(getPageSize());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (buffer.position() == 0x400) {
                buffer.putInt(0xd4000002); // hvc #0
                buffer.putInt(0xd69f03e0); // eret
                continue;
            }
            buffer.putInt(0xd4201100); // brk #0x88
        }
        UnidbgPointer ptr = UnidbgPointer.pointer(emulator, Hypervisor.REG_VBAR_EL1);
        assert ptr != null;
        ptr.write(buffer.array());
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        try {
            if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) {
                return hypervisor.reg_read_vector(regId - Arm64Const.UC_ARM64_REG_Q0);
            } else {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        try {
            if (vector.length != 16) {
                throw new IllegalStateException("Invalid vector size");
            }

            if (regId >= Arm64Const.UC_ARM64_REG_Q0 && regId <= Arm64Const.UC_ARM64_REG_Q31) {
                hypervisor.reg_set_vector(regId - Arm64Const.UC_ARM64_REG_Q0, vector);
            } else {
                throw new UnsupportedOperationException("regId=" + regId);
            }
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public byte[] mem_read(long address, long size) throws BackendException {
        try {
            return hypervisor.mem_read(address, (int) size);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            hypervisor.mem_write(address, bytes);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        try {
            hypervisor.mem_map(address, size, perms);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_protect(long address, long size, int perms) throws BackendException {
        try {
            hypervisor.mem_protect(address, size, perms);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        try {
            hypervisor.mem_unmap(address, size);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(EventMemHook callback, int type, Object user_data) throws BackendException {
    }

    protected InterruptHookNotifier interruptHookNotifier;

    @Override
    public void hook_add_new(InterruptHook callback, Object user_data) throws BackendException {
        if (interruptHookNotifier != null) {
            throw new IllegalStateException();
        } else {
            interruptHookNotifier = new InterruptHookNotifier(callback, user_data);
        }
    }

    protected final void callSVC(long pc, int swi) {
        if (log.isDebugEnabled()) {
            log.debug("callSVC pc=0x" + Long.toHexString(pc) + ", until=0x" + Long.toHexString(until) + ", swi=" + swi);
        }
        if (pc == until) {
            emu_stop();
            return;
        }
        interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_SWI, swi);
    }

    @Override
    public void hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    protected long until;

    @Override
    public final synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        if (log.isDebugEnabled()) {
            log.debug("emu_start begin=0x" + Long.toHexString(begin) + ", until=0x" + Long.toHexString(until) + ", timeout=" + timeout + ", count=" + count);
        }
        this.until = until + 4;
        try {
            hypervisor.emu_start(begin);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void emu_stop() throws BackendException {
        try {
            hypervisor.emu_stop();
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void destroy() throws BackendException {
        IOUtils.close(hypervisor);
    }

    @Override
    public int getPageSize() {
        return pageSize;
    }
}
