package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

public abstract class DynarmicBackend implements Backend, DynarmicCallback {

    private static final Log log = LogFactory.getLog(DynarmicBackend.class);

    static DynarmicBackend tryInitialize(Emulator<?> emulator, boolean is64Bit) {
        try {
            Dynarmic dynarmic = new Dynarmic(is64Bit);
            return is64Bit ? new DynarmicBackend64(emulator, dynarmic) : new DynarmicBackend32(emulator, dynarmic);
        } catch (Throwable throwable) {
            if (log.isDebugEnabled()) {
                log.debug("initialize dynarmic failed", throwable);
            }
            return null;
        }
    }

    protected final Emulator<?> emulator;
    protected final Dynarmic dynarmic;

    protected DynarmicBackend(Emulator<?> emulator, Dynarmic dynarmic) {
        this.emulator = emulator;
        this.dynarmic = dynarmic;
        this.dynarmic.setDynarmicCallback(this);
    }

    @Override
    public final void switchUserMode() {
        // Only user-mode is emulated, there is no emulation of any other privilege levels.
    }

    @Override
    public final void enableVFP() {
    }

    @Override
    public void emu_start(long begin, long until, long timeout, long count) {
        dynarmic.emu_start(begin);
    }

    @Override
    public void emu_stop() {
        dynarmic.emu_stop();
    }

    @Override
    public void destroy() {
        IOUtils.closeQuietly(dynarmic);
    }

    @Override
    public byte[] mem_read(long address, long size) {
        return dynarmic.mem_read(address, (int) size);
    }

    @Override
    public void mem_write(long address, byte[] bytes) {
        dynarmic.mem_write(address, bytes);
    }

    @Override
    public void mem_map(long address, long size, int perms) {
        dynarmic.mem_map(address, size, perms);
    }

    @Override
    public void mem_protect(long address, long size, int perms) {
        dynarmic.mem_protect(address, size, perms);
    }

    @Override
    public void mem_unmap(long address, long size) {
        dynarmic.mem_unmap(address, size);
    }

    private EventMemHookNotifier eventMemHookNotifier;

    @Override
    public void hook_add_new(EventMemHook callback, int type, Object user_data) {
        if (eventMemHookNotifier != null) {
            throw new IllegalStateException();
        } else {
            eventMemHookNotifier = new EventMemHookNotifier(callback, type, user_data);
        }
    }

    protected InterruptHookNotifier interruptHookNotifier;

    @Override
    public void hook_add_new(InterruptHook callback, Object user_data) {
        if (interruptHookNotifier != null) {
            throw new IllegalStateException();
        } else {
            interruptHookNotifier = new InterruptHookNotifier(callback, user_data);
        }
    }

    @Override
    public void addBreakPoint(long address) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void removeBreakPoint(long address) {
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
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) {
        return null;
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] reg_read(int regId, int regSize) {
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
