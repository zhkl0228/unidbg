package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.DynarmicException;
import com.github.unidbg.arm.backend.hypervisor.*;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public abstract class HypervisorBackend extends FastBackend implements Backend, HypervisorCallback {

    private static final Log log = LogFactory.getLog(HypervisorBackend.class);

    static HypervisorBackend tryInitialize(Emulator<?> emulator, boolean is64Bit) throws BackendException {
        try {
            Hypervisor hypervisor = new Hypervisor(is64Bit);
            return is64Bit ? new HypervisorBackend64(emulator, hypervisor) : new HypervisorBackend32(emulator, hypervisor);
        } catch (Throwable throwable) {
            if (log.isDebugEnabled()) {
                log.debug("initialize hypervisor failed", throwable);
            }
            return null;
        }
    }

    protected final Hypervisor hypervisor;

    private static final long REG_VBAR_EL1 = 0xf0000000L;

    protected HypervisorBackend(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        super(emulator);
        this.hypervisor = hypervisor;
        try {
            this.hypervisor.setHypervisorCallback(this);
        } catch (HypervisorException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void onInitialize() {
        super.onInitialize();

        mem_map(REG_VBAR_EL1, getPageSize(), UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        ByteBuffer buffer = ByteBuffer.allocate(getPageSize());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (buffer.position() == 0x400) {
                buffer.putInt(0xd4000002); // hvc #0
            } else {
                buffer.putInt(0xd4000003); // smc #0
            }
//            buffer.putInt(0xd4200000); // brk #0
            buffer.putInt(0xd69f03e0); // eret
        }
        UnidbgPointer ptr = UnidbgPointer.pointer(emulator, REG_VBAR_EL1);
        assert ptr != null;
        ptr.write(buffer.array());
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        return null;
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        throw new UnsupportedOperationException();
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
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        return null;
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) throws BackendException {
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

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    protected long until;

    @Override
    public void emu_start(long begin, long until, long timeout, long count) throws BackendException {
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
        IOUtils.closeQuietly(hypervisor);
    }

    @Override
    public void context_restore(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void context_save(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long context_alloc() {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getPageSize() {
        return 0x4000;
    }
}
