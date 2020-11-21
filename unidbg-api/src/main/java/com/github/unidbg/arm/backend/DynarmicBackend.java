package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.dynarmic.*;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Unicorn;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public abstract class DynarmicBackend extends AbstractBackend implements Backend, DynarmicCallback {

    private static final Log log = LogFactory.getLog(DynarmicBackend.class);

    static DynarmicBackend tryInitialize(Emulator<?> emulator, boolean is64Bit) throws BackendException {
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

    protected DynarmicBackend(Emulator<?> emulator, Dynarmic dynarmic) throws BackendException {
        this.emulator = emulator;
        this.dynarmic = dynarmic;
        try {
            this.dynarmic.setDynarmicCallback(this);
        } catch (DynarmicException e) {
            throw new BackendException(e);
        }
    }

    private static final int EXCEPTION_BREAKPOINT = 8;

    @Override
    public void handleExceptionRaised(long pc, int exception) {
        try {
            if (exception == EXCEPTION_BREAKPOINT) {
                removeBreakPoint(pc);
            }
            emulator.attach().debug();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void handleMemoryReadFailed(long vaddr, int size) {
        try {
            emulator.attach().debug();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void handleMemoryWriteFailed(long vaddr, int size) {
        try {
            emulator.attach().debug();
        } catch (Exception e) {
            e.printStackTrace();
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
    public final void emu_start(long begin, long until, long timeout, long count) throws BackendException {
        if (log.isDebugEnabled()) {
            log.debug("emu_start begin=0x" + Long.toHexString(begin) + ", until=0x" + Long.toHexString(until) + ", timeout=" + timeout + ", count=" + count);
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
        IOUtils.closeQuietly(dynarmic);
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

    private static class SoftBreakPoint implements BreakPoint {
        final long address;
        final byte[] backup;
        final BreakPointCallback callback;
        final boolean thumb;
        SoftBreakPoint(long address, byte[] backup, BreakPointCallback callback, boolean thumb) {
            this.address = address;
            this.backup = backup;
            this.callback = callback;
            this.thumb = thumb;
        }
        @Override
        public void setTemporary(boolean temporary) {
            throw new UnsupportedOperationException();
        }
        @Override
        public boolean isTemporary() {
            return false;
        }
        @Override
        public BreakPointCallback getCallback() {
            return callback;
        }
        @Override
        public boolean isThumb() {
            return thumb;
        }
    }

    private int svcNumber = 1;
    private final Map<Integer, SoftBreakPoint> softBreakpointMap = new HashMap<>();

    @Override
    public BreakPoint addBreakPoint(long address, BreakPointCallback callback, boolean thumb) {
        int svcNumber = ++this.svcNumber; // begin with 2
        byte[] code = addSoftBreakPoint(address, svcNumber, thumb);

        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        byte[] backup = pointer.getByteArray(0, code.length);
        pointer.write(0, code, 0, code.length);
        SoftBreakPoint breakPoint = new SoftBreakPoint(address, backup, callback, thumb);
        softBreakpointMap.put(svcNumber, breakPoint);
        return breakPoint;
    }

    protected abstract byte[] addSoftBreakPoint(long address, int svcNumber, boolean thumb);

    @Override
    public boolean removeBreakPoint(long address) {
        address &= (~1);

        for (Iterator<Map.Entry<Integer, SoftBreakPoint>> iterator = softBreakpointMap.entrySet().iterator(); iterator.hasNext(); ) {
            Map.Entry<Integer, SoftBreakPoint> entry = iterator.next();
            SoftBreakPoint breakPoint = entry.getValue();
            if (address == breakPoint.address) {
                Pointer pointer = UnidbgPointer.pointer(emulator, address);
                assert pointer != null;
                pointer.write(0, breakPoint.backup, 0, breakPoint.backup.length);
                iterator.remove();
                return true;
            }
        }
        return false;
    }

    @Override
    public void setSingleStep(int singleStep) {
    }

    @Override
    public void setFastDebug(boolean fastDebug) {
    }

    @Override
    public Unicorn.UnHook hook_add_new(CodeHook callback, long begin, long end, Object user_data) {
        return null;
    }

    @Override
    public Unicorn.UnHook debugger_add(DebugHook callback, long begin, long end, Object user_data) {
        return null;
    }

    @Override
    public void hook_add_new(ReadHook callback, long begin, long end, Object user_data) {
    }

    @Override
    public void hook_add_new(WriteHook callback, long begin, long end, Object user_data) {
    }

    @Override
    public Unicorn.UnHook hook_add_new(BlockHook callback, long begin, long end, Object user_data) {
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
