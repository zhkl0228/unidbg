package com.github.unidbg.pointer;

import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.BlockHook;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.DebugHook;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.backend.InterruptHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

import java.util.Arrays;

class ByteArrayBackend implements Backend {

    private final byte[] data;

    ByteArrayBackend(byte[] data) {
        this.data = data;
    }

    @Override
    public void onInitialize() {
        throw new UnsupportedOperationException();
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
        return Arrays.copyOfRange(data, (int) address, (int) (address + size));
    }

    @Override
    public void mem_write(long address, byte[] bytes) throws BackendException {
        System.arraycopy(bytes, 0, data, (int) address, bytes.length);
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
    public void hook_add_new(CodeHook callback, long begin, long end, Object user_data) throws BackendException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void debugger_add(DebugHook callback, long begin, long end, Object user_data) throws BackendException {
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
    public void hook_add_new(BlockHook callback, long begin, long end, Object user_data) throws BackendException {
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

    @Override
    public void context_free(long context) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getPageSize() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void registerEmuCountHook(long emu_count) {
        throw new UnsupportedOperationException();
    }
}
