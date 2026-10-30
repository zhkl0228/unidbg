package com.github.unidbg.pointer;

import com.github.unidbg.arm.backend.*;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.BreakPointCallback;

import java.util.Arrays;

class ByteArrayBackend extends AbstractBackend implements Backend {

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
    public long mem_read_value(long address, int size) throws BackendException {
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            throw new IllegalArgumentException("Invalid scalar size: " + size);
        }
        int start = (int) address;
        if (start < 0 || start > data.length || size > Integer.MAX_VALUE - start) {
            byte[] bytes = mem_read(address, size);
            long value = 0;
            for (int i = 0; i < size; i++) {
                value |= (bytes[i] & 0xffL) << (i * 8);
            }
            return value;
        }
        // Arrays.copyOfRange pads reads beyond the end with zeroes. Preserve
        // that behavior, and its int address conversion, without a copy.
        int count = Math.min(size, data.length - start);
        long value = 0;
        for (int i = 0; i < count; i++) {
            value |= (data[start + i] & 0xffL) << (i * 8);
        }
        return value;
    }

    @Override
    public void mem_write_value(long address, long value, int size) throws BackendException {
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            throw new IllegalArgumentException("Invalid scalar size: " + size);
        }
        int start = (int) address;
        if (start < 0 || start > data.length || size > data.length - start) {
            // Keep System.arraycopy's bounds failures and all-or-nothing write.
            byte[] bytes = new byte[size];
            for (int i = 0; i < size; i++) {
                bytes[i] = (byte) (value >>> (i * 8));
            }
            mem_write(address, bytes);
            return;
        }
        for (int i = 0; i < size; i++) {
            data[start + i] = (byte) (value >>> (i * 8));
        }
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
    public void removeJitCodeCache(long begin, long end) throws BackendException {
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
