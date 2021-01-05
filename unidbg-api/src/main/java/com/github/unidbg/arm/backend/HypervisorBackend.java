package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.DynarmicException;
import com.github.unidbg.arm.backend.hypervisor.Hypervisor;
import com.github.unidbg.arm.backend.hypervisor.HypervisorBackend32;
import com.github.unidbg.arm.backend.hypervisor.HypervisorBackend64;
import com.github.unidbg.arm.backend.hypervisor.HypervisorCallback;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

public abstract class HypervisorBackend extends AbstractBackend implements Backend, HypervisorCallback {

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

    protected final Emulator<?> emulator;
    protected final Hypervisor hypervisor;

    protected HypervisorBackend(Emulator<?> emulator, Hypervisor hypervisor) throws BackendException {
        this.emulator = emulator;
        this.hypervisor = hypervisor;
        try {
            this.hypervisor.setHypervisorCallback(this);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void switchUserMode() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void enableVFP() {
        throw new UnsupportedOperationException();
    }

    @Override
    public Number reg_read(int regId) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] reg_read_vector(int regId) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reg_write_vector(int regId, byte[] vector) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void reg_write(int regId, Number value) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] mem_read(long address, long size) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_protect(long address, long size, int perms) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeBreakPoint(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setSingleStep(int singleStep) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setFastDebug(boolean fastDebug) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(InterruptHook callback, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void emu_stop() throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void destroy() throws BackendException {
        throw new UnsupportedOperationException();
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
}
