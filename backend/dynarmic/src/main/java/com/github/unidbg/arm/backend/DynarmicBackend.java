package com.github.unidbg.arm.backend;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.dynarmic.Dynarmic;
import com.github.unidbg.arm.backend.dynarmic.DynarmicCallback;
import com.github.unidbg.arm.backend.dynarmic.DynarmicException;
import com.github.unidbg.arm.backend.dynarmic.EventMemHookNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class DynarmicBackend extends FastBackend implements Backend, DynarmicCallback {

    private static final Logger log = LoggerFactory.getLogger(DynarmicBackend.class);

    protected final Dynarmic dynarmic;

    protected DynarmicBackend(Emulator<?> emulator, Dynarmic dynarmic) throws BackendException {
        super(emulator);
        this.dynarmic = dynarmic;
        try {
            this.dynarmic.setDynarmicCallback(this);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public final boolean handleInterpreterFallback(long pc, int num_instructions) {
        interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_UDEF, 0);
        return false;
    }

    private static final int EXCEPTION_BREAKPOINT = 8;

    @Override
    public void handleExceptionRaised(long pc, int exception) {
        if (exception == EXCEPTION_BREAKPOINT) {
            interruptHookNotifier.notifyCallSVC(this, ARMEmulator.EXCP_BKPT, 0);
            return;
        }
        try {
            emulator.attach().debug();
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    @Override
    public void handleMemoryReadFailed(long vaddr, int size) {
        if (eventMemHookNotifier != null) {
            eventMemHookNotifier.handleMemoryReadFailed(this, vaddr, size);
        }
    }

    @Override
    public void handleMemoryWriteFailed(long vaddr, int size) {
        if (eventMemHookNotifier != null) {
            eventMemHookNotifier.handleMemoryWriteFailed(this, vaddr, size);
        }
    }

    @Override
    public final void switchUserMode() {
        // Only user-mode is emulated, there is no emulation of any other privilege levels.
    }

    @Override
    public final void enableVFP() {
    }

    protected long until;

    @Override
    public final synchronized void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        if (log.isDebugEnabled()) {
            log.debug("emu_start begin=0x{}, until=0x{}, timeout={}, count={}", Long.toHexString(begin), Long.toHexString(until), timeout, count);
        }
        this.until = until + 4;
        try {
            dynarmic.emu_start(begin);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void emu_stop() throws BackendException {
        try {
            dynarmic.emu_stop();
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void destroy() {
        IOUtils.close(dynarmic);
    }

    @Override
    public byte[] mem_read(long address, long size) throws BackendException {
        try {
            return dynarmic.mem_read(address, (int) size);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        try {
            dynarmic.mem_write(address, bytes);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_map(long address, long size, int perms) throws BackendException {
        try {
            dynarmic.mem_map(address, size, perms);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_protect(long address, long size, int perms) throws BackendException {
        try {
            dynarmic.mem_protect(address, size, perms);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    @Override
    public void mem_unmap(long address, long size) throws BackendException {
        try {
            dynarmic.mem_unmap(address, size);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
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
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void debugger_add(DebugHook callback, long begin, long end, Object user_data) {
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
    public void hook_add_new(BlockHook callback, long begin, long end, Object user_data) {
        throw new UnsupportedOperationException();
    }

    @Override
    public long context_alloc() {
        return dynarmic.context_alloc();
    }

    @Override
    public void context_free(long context) {
        Dynarmic.free(context);
    }

    @Override
    public void context_save(long context) {
        dynarmic.context_save(context);
    }

    @Override
    public void context_restore(long context) {
        dynarmic.context_restore(context);
    }
}
